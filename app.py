# import pylance
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import sha256_crypt
from sqlalchemy.exc import IntegrityError
import secrets
import string
import re
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure your SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///proterp.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = datetime.timedelta(minutes=50)
db = SQLAlchemy(app)


# Define the User model
class User(db.Model):
    f_name = db.Column(db.String(100))
    s_name = db.Column(db.String(100))
    email = db.Column(db.String(100), primary_key = True)
    password = db.Column(db.String(255))
    salt = db.Column(db.String(255))

    def __init__(self, f_name, l_name, email, password, salt):
        self.email = email
        self.f_name = f_name
        self.l_name = l_name
        self.password = password
        self.salt = salt

# Define the Student model
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    major = db.Column(db.String(80), nullable=False)
    user_mail = db.Column(db.Integer, db.ForeignKey('user.email'), nullable=False)
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

def passwordValidation(password):
    lowercase_regex = r'[a-z]'
    uppercase_regex = r'[A-Z]'
    digit_regex = r'\d'
    special_chars_regex = r'[!@#$%^&*()_+=-]'
    length_regex = r'^.{8,}$'
    
    conditions = [
    bool(re.search(lowercase_regex, password)),
    bool(re.search(uppercase_regex, password)),
    bool(re.search(digit_regex, password)),
    bool(re.search(special_chars_regex, password)),
    bool(re.search(length_regex, password))
    ]

    return all(conditions)

@app.route('/')
def home():
    try:
        user = session['user']
        if User.query.filter(User.email == user):
            students = Student.query.all()
            courses = Course.query.all()
            return render_template('index.html', students=students, courses=courses)
    except:
        flash("You'll need to login first")
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        receivedToken = request.form['token']

        if session['token'] == receivedToken:

            user = User.query.filter(User.email == email).first()
            user_salt = user.salt
            saltedSecret = password + user_salt
            if sha256_crypt.verify(saltedSecret, user.password):
                session.pop('token', None)
                session['user'] = user.email
                flash("Login Successfull")
                return redirect(url_for('home'))
            else:
                flash("Wrong email or password")
                return redirect(url_for("login"))
        else:
            flash("Time out try again!")
            return redirect(url_for("login"))
    else:
        characters = list(string.ascii_letters + string.digits)
        token = ''.join(secrets.choice(characters)for _ in range(16))
        session['token'] = token
        return render_template("login.html", title="Login", token=token)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    characters = list(string.ascii_letters + string.digits)
    if request.method == "POST":
        receivedToken = request.form['token']
        f_name = request.form['f-name']
        s_name = request.form['s-name']
        email = request.form['email']
        password = request.form['password']
        password2 = request.form['password2']
        salt = ''.join(secrets.choice(characters) for _ in range(24))
        if session['token'] and session['token'] == receivedToken:
            if len(f_name) > 0 and len(s_name) > 0 and len(email) > 0 and \
                len(password) > 0 and len(password2) > 0:
                if password2 == password:
                    if passwordValidation(password):
                        salted_password = password + salt
                        hashed_password = sha256_crypt.hash(salted_password)
                        newUser = User(f_name, s_name, email, hashed_password, salt)
                        try:
                            db.session.add(newUser)
                            db.session.commit()
                            session.pop('token', None)
                            flash("User Registered Sussessfully! Login")
                            return redirect(url_for("login"))
                        except IntegrityError:
                            flash(f'Email already used!')
                            return redirect(url_for('signup'))
                    else:
                        flash("Password criterion not met!")
                        return redirect(url_for('signup'))
                    
                else:
                    flash("Passwords do not match!")
                    return redirect(url_for("signup"))
            else:
                flash("All Fields are Required!")
                return redirect(url_for("signup"))
        else:
            flash("Try Again")
            return redirect(url_for("signup"))
    else:
        token = ''.join(secrets.choice(characters)for _ in range(16))
        session['token'] = token
        return render_template("signup.html", title="Signup", token=token)

@app.route('/upload', methods=['POST'])
def upload():
    try:
        user = session['user']
        if User.query.filter(User.email == user):
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
    except:
        flash("You'll need to login first")
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
