import pylance
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_uploads import UploadSet, configure_uploads, DOCUMENTS

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key

# Configure your SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_portal.db'
db = SQLAlchemy(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Configure Flask-Uploads
documents = UploadSet('documents', DOCUMENTS)
app.config['UPLOADED_DOCUMENTS_DEST'] = 'uploads'
configure_uploads(app, documents)

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Define the Student model
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    major = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='student', uselist=False)

# Define the Course model
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)

# Define the Document model
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    student = db.relationship('Student', backref='documents')
    file = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    students = Student.query.all()
    courses = Course.query.all()
    return render_template('index.html', students=students, courses=courses)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        major = request.form['major']

        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another username.', 'danger')
        else:
            # Create a new user and student record
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()

            student = Student(name=name, major=major, user=user)
            db.session.add(student)
            db.session.commit()

            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'document' in request.files:
        document = request.files['document']
        if document:
            document.save('uploads/' + document.filename)

            # Save the uploaded document in the database
            new_document = Document(student=current_user.student, file=document.filename)
            db.session.add(new_document)
            db.session.commit()

            flash('Document uploaded successfully!', 'success')
        else:
            flash('No file selected for upload.', 'danger')

    return redirect(url_for('home'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
