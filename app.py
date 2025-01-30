<<<<<<< HEAD
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

import models


@app.route("/")
def home():
    return render_template('index.html')

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/register")
def register():
    return render_template('register.html')


if __name__ == "__main__":
=======
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Subject, Chapter


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'BK-3QBD15JF8ZuaG5F6HAqMNEHIcHaqQ2Mdz5nvd6kZA4TigbRfGv99-unD7Smo8fOU'

# import models
# from models import db, User

# models.db.init_app(app)
db.init_app(app)
app.app_context().push()

with app.app_context():
    db.create_all()

import routes


# with app.app_context():
#     db.create_all()

if __name__ == "__main__":
>>>>>>> ae29e00 (Built Admin dashboard with CRUD operations for subjects)
    app.run(debug=True)