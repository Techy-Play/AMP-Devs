from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from models import db, User, Question, Answer, Event, Job
import os
from sqlalchemy import or_

app = Flask(__name__)
app.config['SECRET_KEY'] = '123456'  
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
                role='admin',
                profile_image='@images/default.png'  
            )
            admin.set_password('admin')  
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
    # Check if admin login is requested via query parameter
    login_type = request.args.get('type', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_type = request.form.get('user_type')
        
        # Admin specific login logic
        if user_type == 'admin':
            if username == 'admin' and password == 'admin':
                # Check if admin user exists in database
                admin = User.query.filter_by(username='admin', role='admin').first()
                
                # Create admin user if it doesn't exist
                if not admin:
                    admin = User(
                        username='admin',
                        email='admin@campus2career.com',
                        name='Administrator',
                        role='admin',
                        profile_image='images/default.png'  # Make sure this exists
                    )
                    admin.set_password('admin')
                    db.session.add(admin)
                    db.session.commit()
                
                login_user(admin)
                flash('Welcome to the admin dashboard')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid admin credentials')
        # Regular user login
        else:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password) and user.role == user_type:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password')
    
    # Pass login_type to template
    return render_template('auth/login.html', login_type=login_type)

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
    return render_template('dashboard/admin.html', users=users, events=events, questions=questions, jobs=jobs, now=datetime.now())

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

@app.route('/admin', methods=['GET', 'POST'])
@app.route('/admin/<action>', methods=['GET', 'POST'])
@login_required
def admin_dashboard_action(action=None):
    if current_user.role != 'admin':
        flash('You do not have permission to access the admin dashboard')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if action == 'delete_user':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully')
            else:
                flash('User not found')
            return redirect(url_for('admin_dashboard_action'))

        elif action == 'delete_event':
            event_id = request.form.get('event_id')
            event = Event.query.get(event_id)
            if event:
                db.session.delete(event)
                db.session.commit()
                flash('Event deleted successfully')
            else:
                flash('Event not found')
            return redirect(url_for('admin_dashboard_action'))

        elif action == 'delete_job':
            job_id = request.form.get('job_id')
            job = Job.query.get(job_id)
            if job:
                db.session.delete(job)
                db.session.commit()
                flash('Job deleted successfully')
            else:
                flash('Job not found')
            return redirect(url_for('admin_dashboard_action'))

        elif action == 'post_job':
            job_title = request.form.get('job_title')
            company = request.form.get('company')
            job_description = request.form.get('job_description')
            new_job = Job(title=job_title, company=company, description=job_description, posted_by=current_user.id)
            db.session.add(new_job)
            db.session.commit()
            flash('Job posted successfully')
            return redirect(url_for('admin_dashboard_action'))

        elif action == 'create_event':
            event_title = request.form.get('event_title')
            event_description = request.form.get('event_description')
            event_date_str = request.form.get('event_date')
            
            # Convert the date string to a datetime object
            event_date = datetime.strptime(event_date_str, '%Y-%m-%dT%H:%M')
            
            new_event = Event(title=event_title, description=event_description, date=event_date, created_by=current_user.id)
            db.session.add(new_event)
            db.session.commit()
            flash('Event created successfully')
            return redirect(url_for('admin_dashboard_action'))

        elif action == 'add_user':
            username = request.form.get('username')
            email = request.form.get('email')
            name = request.form.get('name')
            role = request.form.get('role')
            password = request.form.get('password')
            
            if User.query.filter_by(username=username).first():
                flash(f'Username {username} already exists')
                return redirect(url_for('admin_dashboard_action'))
                
            if User.query.filter_by(email=email).first():
                flash(f'Email {email} already exists')
                return redirect(url_for('admin_dashboard_action'))
            
            new_user = User(
                username=username,
                email=email,
                name=name,
                role=role,
                profile_image='noimg.jpg'
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'User {username} created successfully')
            return redirect(url_for('admin_dashboard_action'))
        
        elif action == 'update_user':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user:
                user.username = request.form.get('username')
                user.email = request.form.get('email')
                user.name = request.form.get('name')
                user.role = request.form.get('role')
                
                new_password = request.form.get('password')
                if new_password:
                    user.set_password(new_password)
                
                db.session.commit()
                flash(f'User {user.username} updated successfully')
            else:
                flash('User not found')
            return redirect(url_for('admin_dashboard_action'))

        elif action == 'delete_question':
            question_id = request.form.get('question_id')
            question = Question.query.get(question_id)
            if question:
                db.session.delete(question)
                db.session.commit()
                flash('Question deleted successfully')
            else:
                flash('Question not found')
            return redirect(url_for('admin_dashboard_action'))
    
    users = User.query.all()
    events = Event.query.all()
    jobs = Job.query.all()
    return render_template('dashboard/admin.html', users=users, events=events, jobs=jobs, now=datetime.now())

@app.route('/search')
def search_users():
    query = request.args.get('q', '').strip().lower()
    if len(query) < 2:
        return render_template('search_results.html', users=[])

    # Search users by username
    users = User.query.filter(User.username.ilike(f'%{query}%')).all()
    
    return render_template('search_results.html', users=users)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/jobs')
def job_listings():
    jobs = Job.query.all()  # Fetch all jobs
    return render_template('jobs.html', jobs=jobs)

if __name__ == '__main__':
    init_db()
    app.run(host=0.0.0.0, port=8080,debug=True)
