from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import InputRequired, EqualTo, Email
from flask_wtf.csrf import CSRFProtect
import bcrypt
from pymongo import MongoClient
from PIL import Image
import pytesseract
import re
import os
import time
from datetime import datetime, timedelta
from bson import ObjectId
from werkzeug.utils import secure_filename

# Initialize Flask App
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'uploads'

# CSRF protection
csrf = CSRFProtect(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['aek_noc']
users = db['users']
applications = db['applications']

# Path to tesseract executable
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Function to process uploaded document and detect errors
def detect_document_content(image_path):
    try:
        img = Image.open(image_path)
        extracted_text = pytesseract.image_to_string(img)

        aadhar_pattern = r'\d{4} \d{4} \d{4}'
        pan_pattern = r'[A-Z]{5}[0-9]{4}[A-Z]{1}'

        aadhar_match = re.search(aadhar_pattern, extracted_text)
        pan_match = re.search(pan_pattern, extracted_text)

        errors = []
        if not aadhar_match:
            errors.append("Aadhar number not found or invalid format.")
        if not pan_match:
            errors.append("PAN number not found or invalid format.")

        return extracted_text, errors
    except Exception as e:
        return "", [str(e)]

# Function to send notification emails
def send_email(subject, recipient, body):
    try:
        msg = Message(subject, sender="your_email@gmail.com", recipients=[recipient])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        flash(f"Error sending email: {e}", 'danger')

# Custom filter to format datetime
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if value is None:
        return ''
    return value.strftime(format)

# Register the custom filter
app.jinja_env.filters['datetime'] = format_datetime

# Flask-WTF Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    name = StringField('Full Name', validators=[InputRequired()])
    email = StringField('Email Address', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    role = SelectField('Register As', choices=[('admin', 'Admin'), ('manager', 'Manager'), ('inspector', 'Inspector')])
    submit = SubmitField('Register')

# Route: Index (Home Page)
@app.route('/')
def index():
    return render_template('index.html')

# Route: Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode('utf-8')

        user = users.find_one({'username': username})
        if user and bcrypt.checkpw(password, user['password']):
            session['username'] = username
            session['role'] = user.get('role', 'user')
            flash('Login successful!', 'success')
            session.permanent = True

            # Redirect based on user role
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)

# Route: Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        role = form.role.data

        if users.find_one({'username': username}):
            flash('Username already exists!', 'danger')
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users.insert_one({'username': username, 'name': name, 'email': email, 'password': hashed_password, 'role': role})
            flash('Registration successful!', 'success')

            send_email('Registration Successful', email, 'Thank you for registering with AEK NOC System.')

            return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Route: Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    applications_list = applications.find()
    return render_template('admin_dashboard.html', applications=applications_list)

# Route: Approve/Reject NOC
@app.route('/approve_noc/<app_id>', methods=['POST'])
def approve_noc(app_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    action = request.form.get('action')
    application = applications.find_one({'_id': ObjectId(app_id)})

    if action == 'approve':
        applications.update_one({'_id': ObjectId(app_id)}, {'$set': {'status': 'approved'}})
        flash('NOC Approved!', 'success')
        send_email('NOC Approved', application['email'], 'Your NOC application has been approved.')
    elif action == 'reject':
        applications.update_one({'_id': ObjectId(app_id)}, {'$set': {'status': 'rejected'}})
        flash('NOC Rejected!', 'danger')
        send_email('NOC Rejected', application['email'], 'Your NOC application has been rejected.')

    return redirect(url_for('admin_dashboard'))

# Route: User Dashboard
@app.route('/user_dashboard')
def user_dashboard():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))

    user_applications = applications.find({'username': session['username']})
    return render_template('user_dashboard.html', applications=user_applications)

# Allowed file extensions for document uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg','pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Route: Upload Document
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['document']
        
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Process the file
            extracted_text, errors = detect_document_content(file_path)

            if errors:
                flash(f"Document errors: {', '.join(errors)}", 'danger')
            else:
                flash(f"Document processed successfully: {extracted_text}", 'success')

                # Save the application details
                applications.insert_one({
                    'username': session['username'],
                    'document': filename,
                    'status': 'pending',
                    'timestamp': datetime.now()
                })

            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid file type. Please upload an image.', 'danger')

    return render_template('upload.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# Route: Simple Login Page
@app.route('/login_page')
def login_page():
    return render_template('login.html')

# Route: Simple Dashboard
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        return render_template('dashboard.html')  # Admin Dashboard page
    else:
        return redirect(url_for('login_page'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
