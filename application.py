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
