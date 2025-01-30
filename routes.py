<<<<<<< HEAD
from flask import Flask, render_template
from app import app

=======
from flask import Flask, render_template, current_app as app, request, redirect, url_for, flash, session
from models import db, User, Subject, Chapter
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

admin = User.query.filter_by(is_admin=True).first()
if not admin:
    passhash = generate_password_hash('admin')
    admin = User(username='admin', password_hash=passhash, is_admin=True)
    db.session.add(admin)
    db.session.commit()


@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/login", methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Please fill all fields")
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash("Username does not exist")
        return redirect(url_for('login'))

    if not check_password_hash(user.password_hash, password):
        flash("Invalid password")
        return redirect(url_for('login'))
    # print(url_for('index'))
    # return redirect(url_for('home'))

    session['user_id'] = user.id
    flash("Login successful")
    return redirect(url_for('home'))

@app.route("/register")
def register():
    return render_template('register.html')

@app.route("/register", methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    qualification = request.form.get('qualification')
    dob = request.form.get('date')
    
    if not username or not password or not qualification:
        flash('Please fill all fields')
        return redirect(url_for('register'))

    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists')
        return redirect(url_for('register'))
    
    passhash = generate_password_hash(password)

    new_user = User(username=username, password_hash=passhash, full_name=full_name, qualification=qualification, dob=dob)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

def auth_requried(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('You need to be logged in to access this page')
            return redirect(url_for('login'))
    return inner

def admin_requried(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return inner

@app.route("/")
@auth_requried
def home():
    user = User.query.get(session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin'))
    return render_template('index.html')

@app.route("/profile")
@auth_requried
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route("/profile", methods=["POST"])
@auth_requried
def profile_post():
    username = request.form.get('username')
    cpassword = request.form.get('cpassword')
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    dob = request.form.get('date')
    qualification = request.form.get('qualification')

    if not username or not cpassword or not password:
        flash('Please fill all fields')
        return redirect(url_for('profile'))

    user = User.query.get(session['user_id'])
    if not check_password_hash(user.password_hash, cpassword):
        flash("Incorrect password !")
        return redirect(url_for('profile'))

    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash("Username alreay exits")
            return redirect(url_for('profile'))

    new_passhash = generate_password_hash(password)

    user.username = username
    user.password_hash = new_passhash
    user.full_name = full_name
    user.date = dob
    user.qualification = qualification
    db.session.commit()
    flash("Profile Updated")
    return redirect(url_for('profile'))
    

@app.route("/logout")
@auth_requried
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

@app.route("/admin")
@admin_requried
def admin():
    subjects = Subject.query.all()
    print("Subjects found")
    return render_template('admin.html', subjects=subjects)

@app.route("/subject/add")
@admin_requried
def subject_add():
    user = User.query.get(session['user_id'])
    return render_template('subject.html', user=user)

@app.route("/subject/add", methods=['POST'])
def subject_add_post():
    subject_name = request.form.get('name')
    print(subject_name)
    subject_description = request.form.get('description')
    # print("hello")

    if subject_name == '':
        flash("Please enter subject name")
        return redirect(url_for('subject_add'))

    subject = Subject.query.filter_by(name=subject_name).first()
    if subject:
        flash('Subject already exists')
        return redirect(url_for('subject_add'))

    if len(subject_name) > 64:
        flash("Subject name should not exceed 64 characters")
        return redirect(url_for('subject_add'))

    new_subject = Subject(name=subject_name, description=subject_description)
    db.session.add(new_subject)
    db.session.commit()
    flash("Subject added successfully")
    return redirect(url_for('admin'))

@app.route("/subject/<int:id>/edit")
@admin_requried
def edit_subject(id):
    subjects = Subject.query.get(id)
    if not subjects:
        flash("Subject not found")
        return redirect(url_for('admin'))
    return render_template('edit.html', subjects=subjects)

@app.route("/subject/<int:id>/edit", methods=['POST'])
@admin_requried
def edit_subject_post(id):
    subjects = Subject.query.get(id)
    if not subjects:
        flash("Subject not found")
        return redirect(url_for('admin'))
    subject_name = request.form.get('name')
    if not subject_name:
        flash("Please enter subject name")
        return redirect(url_for('edit_subject', id=id))
    subjects.name = subject_name
    db.session.commit()
    flash("Subject updated successfully")
    return redirect(url_for('admin'))

@app.route("/subject/<int:id>/delete")
@admin_requried
def delete_subject(id):
    subjects = Subject.query.get(id)
    if not subjects:
        flash("Subject not found")
        return redirect(url_for('admin'))
    return render_template('delete.html', subjects=subjects)

@app.route("/subject/<int:id>/delete", methods=['POST'])
@admin_requried
def delete_subject_post(id):
    subjects = Subject.query.get(id)
    if not subjects:
        flash("Subject not found")
        return redirect(url_for('admin'))
    db.session.delete(subjects)
    db.session.commit()
    flash("Subject deleted Successfully")
    return redirect(url_for('admin'))
    
>>>>>>> ae29e00 (Built Admin dashboard with CRUD operations for subjects)
