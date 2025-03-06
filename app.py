from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from models import db, User, Question, Answer, Event, Job
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus2career.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
def init_db():
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@campus2career.com',
                role='admin'
            )
            admin.set_password('admin')  # Change this in production
            db.session.add(admin)
            db.session.commit()

# Routes
@app.route('/')
def index():
    events = Event.query.order_by(Event.date.desc()).limit(3).all()
    questions = Question.query.order_by(Question.created_at.desc()).limit(5).all()
    return render_template('index.html', events=events, questions=questions)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_type = request.form.get('user_type')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.role == user_type:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('auth/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        course = request.form.get('course')
        contact = request.form.get('contact')
        dob = datetime.strptime(request.form.get('dob'), '%Y-%m-%d')

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))

        user = User(
            username=username,
            email=email,
            role='student',
            course=course,
            contact=contact,
            dob=dob
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('auth/signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif current_user.role == 'alumni':
        return redirect(url_for('alumni_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

@app.route('/questions', methods=['GET', 'POST'])
def questions():
    if request.method == 'POST' and current_user.is_authenticated:
        title = request.form.get('title')
        content = request.form.get('content')
        question = Question(title=title, content=content, user_id=current_user.id)
        db.session.add(question)
        db.session.commit()
        return redirect(url_for('questions'))
    
    questions = Question.query.order_by(Question.created_at.desc()).all()
    return render_template('questions/list.html', questions=questions)

@app.route('/question/<int:id>', methods=['GET', 'POST'])
def question_detail(id):
    question = Question.query.get_or_404(id)
    if request.method == 'POST' and current_user.is_authenticated:
        content = request.form.get('content')
        answer = Answer(content=content, user_id=current_user.id, question_id=id)
        db.session.add(answer)
        db.session.commit()
    return render_template('questions/detail.html', question=question)

@app.route('/events')
def events():
    events = Event.query.order_by(Event.date.desc()).all()
    return render_template('events/list.html', events=events)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    users = User.query.all()
    events = Event.query.all()
    questions = Question.query.all()
    jobs = Job.query.all()
    return render_template('dashboard/admin.html', users=users, events=events, questions=questions, jobs=jobs)

@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return redirect(url_for('dashboard'))
    events = Event.query.filter_by(created_by=current_user.id).all()
    return render_template('dashboard/teacher.html', events=events)

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('dashboard'))
    questions = Question.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard/student.html', questions=questions)

@app.route('/alumni/dashboard')
@login_required
def alumni_dashboard():
    if current_user.role != 'alumni':
        return redirect(url_for('dashboard'))
    answers = Answer.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard/alumni.html', answers=answers)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        user = User.query.get(current_user.id)
        
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename:
                # Save the file
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.static_folder, 'images', filename))
                user.profile_image = filename

        # Update other fields
        user.email = request.form.get('email')
        user.contact = request.form.get('contact')
        user.course = request.form.get('course')

        # Update password if provided
        new_password = request.form.get('new_password')
        if new_password:
            user.set_password(new_password)

        db.session.commit()
        flash('Profile updated successfully')
        return redirect(url_for('dashboard'))

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
