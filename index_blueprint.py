# This is a sample bit of code to display a home page (blank in this case).
# login_required is specified, so the user will be SAML authenticated if they are not logged in yet.
#

from flask import Blueprint,render_template
from flask_login import login_required

index_blueprint = Blueprint('index_blueprint', __name__)


@index_blueprint.route('/')
@login_required
def index():
	return render_template('index.html')
