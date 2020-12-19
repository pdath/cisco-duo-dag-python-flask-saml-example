# https://github.com/jpf/okta-pysaml2-example/blob/master/app.py

from config import SAML_METADATA_URL,SAML_ENTITY_ID

from flask import (
	Blueprint,
	redirect,
	url_for,
	request,
	render_template,
	jsonify
)

from flask_login import (
	LoginManager,
	UserMixin,
	current_user,
	login_required,
	login_user,
	logout_user,
)

from saml2 import (
	BINDING_HTTP_POST,
	BINDING_HTTP_REDIRECT,
	entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.sigver import SignatureError
import requests

login_blueprint = Blueprint('login_blueprint', __name__)

metadata_url= SAML_METADATA_URL

# We provide zero user management.  We rely on DAG for that.  So if DAG tells us a user is valid and authenticated
# we believe it.  To allow Flask-Login to work and think there is a database of users, we create the users
# that DAG tells us about in an associate array in memory.
login_manager = LoginManager()
login_manager.setup_app(login_blueprint)

user_store = {}

class User(UserMixin):
	def __init__(self, user_id):
		user = {}
		self.id = None
		self.first_name = None
		self.last_name = None
		try:
			user = user_store[user_id]
			self.id = unicode(user_id)
			self.first_name = user['first_name']
			self.last_name = user['last_name']
		except:
			pass

@login_manager.user_loader
def load_user(user_id):
	return User(user_id)

@login_blueprint.login_manager.unauthorized_handler
def custom_401():
	return redirect(url_for("login_blueprint.sp_initiated"))

# This allows @login_required to be called from other blueprints
@login_blueprint.record_once
def on_load(state):
	login_manager.init_app(state.app)


def saml_client_for():
	acs_url = url_for(
		"login_blueprint.idp_initiated",
		_external=True)
	https_acs_url = url_for(
		"login_blueprint.idp_initiated",
		_external=True,
		_scheme='https')

	#   SAML metadata changes very rarely. On a production system,
	#   this data could be cached as approprate for your production system.
	rv = requests.get(metadata_url)

	settings = {
		'entityid': SAML_ENTITY_ID,
		'metadata': {
			'inline': [rv.text],
		},
		'service': {
			'sp': {
				'endpoints': {
					'assertion_consumer_service': [
						(acs_url, BINDING_HTTP_REDIRECT),
						(acs_url, BINDING_HTTP_POST),
						(https_acs_url, BINDING_HTTP_REDIRECT),
						(https_acs_url, BINDING_HTTP_POST)
						],
					},
					# Don't verify that the incoming requests originate from us via
					# the built-in cache for authn request ids in pysaml2
					'allow_unsolicited': True,
					# Don't sign authn requests, since signed requests only make
					# sense in a situation where you control both the SP and IdP
					'authn_requests_signed': False,
					'logout_requests_signed': True,
					'want_assertions_signed': True,
					'want_response_signed': False,
				},
			},
	}

	spConfig = Saml2Config()
	spConfig.load(settings)
	spConfig.allow_unknown_attributes = True
	saml_client = Saml2Client(config=spConfig)
	return saml_client

@login_blueprint.route("/saml/acs/", methods=['POST'])
def idp_initiated():
	try:
		saml_client = saml_client_for()
		authn_response = saml_client.parse_authn_request_response(
			request.form['SAMLResponse'],
			entity.BINDING_HTTP_POST)
		authn_response.get_identity()
		user_info = authn_response.get_subject()
		username = user_info.text

		# This is what as known as "Just In Time (JIT) provisioning".
		# What that means is that, if a user in a SAML assertion
		# isn't in the user store, we create that user first, then log them in
		if username not in user_store:
			user_store[username] = {
			}
		user = User(username)
		login_user(user)
		# You can change this URL to point to something else if you want the user sent somewhere specific after login
		url = '/'
		# NOTE:
		#   On a production system, the RelayState MUST be checked
		#   to make sure it doesn't contain dangerous URLs!
		if 'RelayState' in request.form:
			url = request.form['RelayState']
		return redirect(url)
	except SignatureError:
		return render_template('acs_error.html', form=form)


@login_blueprint.route('/saml/sso/')
def sp_initiated():
	saml_client = saml_client_for()
	reqid, info = saml_client.prepare_for_authenticate()

	redirect_url = None
	# Select the IdP URL to send the AuthN request to
	for key, value in info['headers']:
		if key == 'Location':
			redirect_url = value
	response = redirect(redirect_url, code=302)
	# NOTE:
	#   I realize I _technically_ don't need to set Cache-Control or Pragma:
	#     http://stackoverflow.com/a/5494469
	#   However, Section 3.2.3.2 of the SAML spec suggests they are set:
	#     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
	#   We set those headers here as a "belt and suspenders" approach,
	#   since enterprise environments don't always conform to RFCs
	response.headers['Cache-Control'] = 'no-cache, no-store'
	response.headers['Pragma'] = 'no-cache'
	return response

@login_blueprint.route('/logout')
def logout():
	logout_user()
	return render_template('logout.html')
