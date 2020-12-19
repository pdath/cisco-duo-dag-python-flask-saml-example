# Introduction

I spent about a week trying to integrate a Python Flask app with Cisco Duo Access Gateway (DAG) using SAML for
authentication.  To save someone else having this experience, I have created this example on how to do it.

This example was designed to work in Amazon AWS Elastic Beanstalk (using Python of course) but will run on any
Linux server that is setup to run a Python Flask app.

This example is heavily based on the below example using pysaml2 for Okta.
https://github.com/jpf/okta-pysaml2-example/blob/master/app.py

I've converted it to a Python Blueprint (hate circular imports) and put all the yucky SAML stuff into a single
module you can mostly ignore.

Flask-Login is used to handle logins on your web app side.

# Terms

SAML has lots of terms.  Here is a quick start to help you understand.

Your application is known as a "Service Provider".  This is often written as "SP".

The Duo DAG is an "Identity Provider".  This is often written as "Idp".

An EntityId is a unique string to identify your app.  The convention for is to use the URL for your web
app as the entity ID.  I wouldn't risk using anything other than the URL for your web app.

# Requirements

I built this example on Windows.  If you are doing the same, you can run build.bat which will create a zip
file ready to upload into Amazon AWS Beanstalk (into a Python 3.x runtime - of course).

I wrote this using Python 3.7.  As long as you stick to 3.x you should be fine.

## If you are not using Amazon AWS Beanstalk

You'll also need:
* A flavour of Linux.
* To install the packages xmlsec1 and xmlsec1-openssl (which is the reason this will not work on Windows).
* To install Python 3.x.
* A framework to run the Python WSGI app such as Gunicorn (Gunicorn is what Amazon AWS Beanstalk uses).
* A public URL (aka a proper public DNS name) pointing to your web app.
* A public SSL certificate.
* To install the Python modules in requirements.txt

Because of this, you are unlikely to be able to run and test this on your personal development machine.

Until you reach the point where you can point a web browser at your web app using https and get no errors it 
is guaranteed not to work.

Also, your application server and Cisco Duo DAG need to have their time synchronised.  I spent a lot of time trying to get it
going only to find out that the DAG server was 20s ahead of my application server - and that was enough to break it.

# The Flow

Let us pretend the URL for your application is https://yourappserver.com, and your DAG server is https://yourdagserver.com.

## Cisco Duo DAG Launcher

If you are using the DAG Launcher (basically its a portal with all your web apps in it):

* When you click on your application in the DAG launcher it will send users to https://yourappserver.com/saml/sso.
* DAG will then authenticate the user and then redirect them back to https://yourappserver.com/saml/acs.

Finished.

## Using your app to trigger the authentication

* Configure your application to send the user to https://yourappserver.com/saml/sso.  This can be a simple link.
* The user will be redirected to the Cisco DAG to be authenticated.
* DAG will then authenticate the user and then redirect them back to https://yourappserver.com/saml/acs.

Finished.

# Configuration

In the example, you need to edit config.py.  Update SAML_METADATA_URL to point to your DAG server.  Update SAML_ENTITY_ID
to be the URL of your web app.

Follow the Duo instructions to configure a generic SAML service provider.
https://duo.com/docs/dag-generic

* "Service Provider Name" is what will get displayed in the DAG Launcher (if you have that enabled).
* "Entity ID" must EXACTLY match the SAML_ENTITY_ID you specified in config.py.
* "Assertion Consumer Service" should be https://yourappserver.com/saml/acs/
* "Single Logout URL" should be left blank.
* "Service Provider Login URL" should be https://yourappserver.com/saml/sso/
* "Default Relay State" should be left blank.

There are lots of other parameters.  Don't mess with them.

# How to use

application.py needs to include the login_blueprint, which is all the yucky SAML stuff.  You should then include any other
blueprints that are needed (aka your code).
For the example, a single blueprint is included called index_blueprint, which is used to display a home page (blank, in this case).

```python
from flask import Blueprint,Flask

from index_blueprint import index_blueprint
from login_blueprint import login_blueprint

application = Flask(__name__)
application.config.from_pyfile('config.py')

application.register_blueprint(index_blueprint)
application.register_blueprint(login_blueprint)

if __name__ == "__main__":
	application.debug = True
	application.run()
```

index_bluerint.py is an example of some code you might have in your app.  In this case, it simply displays a blank page.  The
important bit is the decorator @login_required.  You need to put this before anything in your app that requires the user to be
logged in via Cisco Duo DAG.

## index_blueprint.py:

```python
from flask import Blueprint,render_template
from flask_login import login_required

index_blueprint = Blueprint('index_blueprint', __name__)


@index_blueprint.route('/')
@login_required
def index():
	return render_template('index.html')
```

The login_blueprint.py module will automatically trigger a SAML login if the user attempts to access something that
needs a login, but is not yet SAML authenticated.
