from flask import Flask, render_template, current_app as app, request, redirect, url_for, flash, session
from models import db, User, Subject, Chapter, Quiz, Question
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

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


@app.route('/quiz')
@auth_requried
def quiz_management():
    user = User.query.get(session['user_id'])
    quizzes = Quiz.query.all()
    return render_template('quiz.html', quizzes=quizzes, user=user)

@app.route('/quiz/<int:id>/delete')
@auth_requried
def delete_quiz(id):
    quiz = Quiz.query.get(id)
    if not quiz:
        flash("Quiz not found")
        return redirect(url_for('quiz_management'))
    
    try:
        # First delete all associated questions
        Question.query.filter_by(quiz_id=id).delete()
        # Then delete the quiz
        db.session.delete(quiz)
        db.session.commit()
        flash("Quiz deleted Successfully")
    except Exception as e:
        db.session.rollback()
        flash("Error deleting quiz")
    
    return redirect(url_for('quiz_management'))

@app.route('/quiz/<int:id>/live')
@auth_requried
def live_quiz(id):
    return 'live quiz'

@app.route('/quiz/<int:id>/show')
@auth_requried
def show_quiz(id):
    return 'Show quiz'

@app.route('/quiz/<int:id>/edit')
@auth_requried
def edit_quiz(id):
    user = User.query.get(session['user_id'])
    quiz = Quiz.query.get_or_404(id)
    return render_template('edit_quiz.html', quiz=quiz, user=user)

@app.route('/quiz/<int:id>/edit', methods=['POST'])
@auth_requried
def edit_quiz_post(id):
    quiz = Quiz.query.get_or_404(id)
    
    # Get form data
    quiz.name = request.form.get('quiz_title')
    quiz.no_of_question = request.form.get('no_of_question')
    quiz.marks = request.form.get('marks')
    quiz.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
    quiz.time = request.form.get('time')
    quiz.remark = request.form.get('remark')
    
    try:
        db.session.commit()
        flash('Quiz updated successfully')
    except:
        db.session.rollback()
        flash('Error updating quiz')
    
    return redirect(url_for('quiz_management'))

@app.route('/quiz/<int:id>/add_question')
@auth_requried
def add_question(id):
    quiz = Quiz.query.get_or_404(id)
    return render_template('question.html', quiz=quiz)

@app.route('/quiz/<int:id>/add_question', methods=['POST'])
@auth_requried
def add_question_post(id):
    quiz = Quiz.query.get_or_404(id)
    
    # Get form data
    question = request.form.get('question_name')
    option1 = request.form.get('option1')
    option2 = request.form.get('option2')
    option3 = request.form.get('option3')
    option4 = request.form.get('option4')
    correct_option = request.form.get('correct_option')
    
    # Create new question
    new_question = Question(
        question_name=question,
        option1=option1,
        option2=option2,
        option3=option3,
        option4=option4,
        correct_option=correct_option,
        quiz_id=id
    )
    
    try:
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully')
    except:
        db.session.rollback()
        flash('Error adding question')
    
    return redirect(url_for('quiz_management'))


@app.route("/quiz/<int:id>/question/<int:question_id>/edit", methods=['GET', 'POST'])
@auth_requried
def edit_question(id, question_id):
    user = User.query.get(session['user_id'])
    question = Question.query.get_or_404(question_id)
    
    if request.method == 'POST':
        # Handle form submission and update question
        question.name = request.form.get('question_name')
        question.option1 = request.form.get('option1')
        question.option2 = request.form.get('option2')
        question.option3 = request.form.get('option3')
        question.option4 = request.form.get('option4')
        question.correct_option = request.form.get('correct_option')
        
        try:
            db.session.commit()
            flash('Question updated successfully')
            return redirect(url_for('quiz_management'))
        except:
            db.session.rollback()
            flash('Error updating question')
            
    return render_template('edit_question.html', question=question, user=user)


@app.route("/quiz/<int:id>/question/<int:question_id>/delete")
@auth_requried
def delete_question(id, question_id):
    question = Question.query.get_or_404(question_id)
    try:
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully')
    except:
        db.session.rollback()
        flash('Error deleting question')
    
    return redirect(url_for('quiz_management'))

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
    return render_template('edit_subject.html', subjects=subjects)

@app.route("/subject/<int:id>/edit", methods=['POST'])
@admin_requried
def edit_subject_post(id):
    subjects = Subject.query.get(id)
    if not subjects:
        flash("Subject not found")
        return redirect(url_for('admin'))
    subject_name = request.form.get('name')
    subject_description = request.form.get('description')
    if not subject_name:
        flash("Please enter subject name")
        return redirect(url_for('edit_subject', id=id))
    subjects.name = subject_name
    subjects.description = subject_description
    db.session.commit()
    flash("Subject updated successfully")
    return redirect(url_for('admin'))

@app.route("/subject/<int:id>/delete")  # Change to GET since we're accessing directly
@admin_requried
def delete_subject(id):
    subject = Subject.query.get(id)
    if not subject:
        flash("Subject not found")
        return redirect(url_for('admin'))
    
    # First delete all associated chapters
    Chapter.query.filter_by(subject_id=id).delete()
    # Then delete the subject
    db.session.delete(subject)
    try:
        db.session.commit()
        flash("Subject deleted Successfully")
    except Exception as e:
        db.session.rollback()
        flash("Error deleting subject")
    
    return redirect(url_for('admin'))


@app.route("/chapter/add")
@admin_requried
def chapter_add():
    user = User.query.get(session['user_id'])
    subject_id = request.args.get('subject_id', type=int)
    if not subject_id:
        flash("No subject selected")
        return redirect(url_for('admin'))
    subject = Subject.query.get_or_404(subject_id)
    return render_template('chapter.html', user=user, subject=subject, chapters=None)

@app.route("/chapter/add", methods=['POST'])
def chapter_add_post():
    chapter_name = request.form.get('name')
    chapter_description = request.form.get('description')
    subject_id = request.args.get('subject_id', type=int)
    
    if not subject_id:
        flash("No subject selected")
        return redirect(url_for('admin'))
    
    subject = Subject.query.get_or_404(subject_id)

    if chapter_name == '':
        flash("Please enter chapter name")
        return redirect(url_for('chapter_add', subject_id=subject_id))

    chapter = Chapter.query.filter_by(name=chapter_name, subject_id=subject_id).first()
    if chapter:
        flash('Chapter already exists')
        return redirect(url_for('chapter_add', subject_id=subject_id))

    if len(chapter_name) > 64:
        flash("Chapter name should not exceed 64 characters")
        return redirect(url_for('chapter_add', subject_id=subject_id))

    new_Chapter = Chapter(name=chapter_name, description=chapter_description, subject_id=subject.id)
    db.session.add(new_Chapter)
    db.session.commit()
    flash("Chapter added successfully")
    return redirect(url_for('admin'))

@app.route("/chapter/<int:id>/edit")
@admin_requried
def edit_chapter(id):
    chapters = Chapter.query.get(id)
    if not chapters:
        flash("Chapter not found")
        return redirect(url_for('admin'))
    return render_template('edit_chapter.html', chapters=chapters)

@app.route("/chapter/<int:id>/edit", methods=['POST'])
@admin_requried
def edit_chapter_post(id):
    chapters = Chapter.query.get(id)
    if not chapters:
        flash("Chapter not found")
        return redirect(url_for('admin'))
    chapter_name = request.form.get('name')
    chapter_description = request.form.get('description')
    if not chapter_name:
        flash("Please enter chapter name")
        return redirect(url_for('edit_chapter', id=id))
    chapters.name = chapter_name
    chapters.description = chapter_description
    db.session.commit()
    flash("Chapter updated successfully")
    return redirect(url_for('admin'))

@app.route("/chapter/<int:id>/delete")
@admin_requried
def delete_chapter(id):
    chapter = Chapter.query.get(id)
    if not chapter:
        flash("Chapter not found")
        return redirect(url_for('admin'))
    
    try:
        db.session.delete(chapter)
        db.session.commit()
        flash("Chapter deleted successfully")
    except Exception as e:
        db.session.rollback()
        flash("Error deleting chapter")
    
    return redirect(url_for('admin'))

@app.route("/chapter/<int:id>/create")
@admin_requried
def create_quiz(id):
    user = User.query.get(session['user_id'])
    # chapter_id = request.args.get('chapter_id', type=int)
    chapter_id = id
    if not chapter_id:
        flash("No chapter selected")
        return redirect(url_for('admin'))
    chapter = Chapter.query.get_or_404(chapter_id)
    return render_template('create_quiz.html', user=user, chapter=chapter)

@app.route("/chapter/<int:chapter_id>/create", methods=['POST'])
@admin_requried
def create_quiz_post(chapter_id):
    quiz_name = request.form.get('quiz_title')
    no_of_question = request.form.get('no_of_question')
    marks = request.form.get('marks')
    date = request.form.get('date')
    time = request.form.get('time')
    remark = request.form.get('remark')

    date = datetime.strptime(date, '%Y-%m-%d')
    
    # Convert time to integer minutes
    time = int(time)

    chapter = Chapter.query.get_or_404(chapter_id)
    if quiz_name == '':
        flash("Please enter quiz name")
        return redirect(url_for('create_quiz', id=chapter_id))

    quiz = Quiz.query.filter_by(name=quiz_name, chapter_id=chapter_id).first()
    if quiz:
        flash('Quiz already exists')
        return redirect(url_for('create_quiz', id=chapter_id))

    # First check for 60 minutes
    if int(time) > 60:
        flash("Time should not exceed 60 minutes")
        return redirect(url_for('create_quiz', id=chapter_id))

    if int(no_of_question) <= 0 or int(marks) <= 0 or int(time) <= 0:
        flash("Number of questions, marks, and time should be positive")
        return redirect(url_for('create_quiz', id=chapter_id))

    if int(no_of_question) > 100:
        flash("Number of questions should not exceed 100")
        return redirect(url_for('create_quiz', id=chapter_id))

    if int(marks) > 100:
        flash("Marks should not exceed 100")
        return redirect(url_for('create_quiz', id=chapter_id))

    new_quiz = Quiz(name=quiz_name, no_of_question=no_of_question, marks=marks, date=date, time=time, remark=remark, chapter_id=chapter.id)
    db.session.add(new_quiz)
    db.session.commit()
    flash("Quiz created successfully")
    return redirect(url_for('admin'))
