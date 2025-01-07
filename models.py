from app import app
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique = True, nullable = False)
    password_hash = db.Column(db.String(256),  nullable = False)
    full_name = db.Column(db.String(100), nullable = True)
    qualification = db.Column(db.String(255), nullable = True)
    dob = db.Column(db.String(20), nullable = True)
    is_admin = db.Column(db.Boolean, nullable = False, default = False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String, nullable = False, unique = True)
    description = db.Column(db.String(150))
    # chapters = db.relationship('Chapter', back)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255), nullable = False)
    description = db.Column(db.String(100))
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable = False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255), nullable = False)
    no_of_chapter = db.Column(db.Integer, nullable = False, foreign_keys = True)
    no_of_question = db.Column(db.Integer, nullable = False)
    marks = db.Column(db.Integer, nullable = False)
    timestamp = db.Column(db.Integer, default=lambda: int(datetime.utcnow().timestamp()))


class Question(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    # name = db.Column(db.String(30), nullable = False)
    description = db.Column(db.String(100), nullable = True)
    option1 = db.Column(db.String(50), nullable = False)
    option2 = db.Column(db.String(50), nullable = False)
    option3 = db.Column(db.String(50), nullable = False)
    option4 = db.Column(db.String(50), nullable = False)
    correct_option = db.Column(db.String(50), nullable = False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable = False)

class Score(db.Model):  
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable = False)
    no_of_attempt = db.Column(db.Integer, nullable = False)
    no_of_correct_question = db.Column(db.Integer, nullable = False)
    timestamp = db.Column(db.Integer, default=lambda: int(datetime.utcnow().timestamp()))

with app.app_context():
    db.create_all()
    # db.session.commit()