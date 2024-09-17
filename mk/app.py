from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
from pymongo import MongoClient
from PIL import Image
import pytesseract
import re
import os
import time

# Initialize Flask App
app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30-minute session timeout

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['aek_noc']
users = db['users']
applications = db['applications']

# Path to tesseract executable (if installed on your machine)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Function to process uploaded document and detect errors
def detect_document_content(image_path):
    try:
        img = Image.open(image_path)  # Open image for OCR
        extracted_text = pytesseract.image_to_string(img)  # Extract text from image using pytesseract

        # Patterns for Aadhar and PAN numbers
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

# Route: Index (Home Page)
@app.route('/')
def index():
    return render_template('index.html')

# Route: Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')

        user = users.find_one({'username': username})
        if user and bcrypt.checkpw(password, user['password']):
            session['username'] = username
            session['role'] = user.get('role', 'user')  # Default to 'user' if role is not set
            flash('Login successful!', 'success')
            session.permanent = True  # Enable session timeout

            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Route: Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        role = request.form.get('role')

        # Check for missing fields
        if not username or not password or not confirm_password:
            flash('Please fill out all fields!', 'danger')
            return redirect(url_for('register'))

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        # Check if username already exists
        if users.find_one({'username': username}):
            flash('Username already exists!', 'danger')
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users.insert_one({'username': username, 'password': hashed_password, 'role': role})
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# Route: Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    applications_list = applications.find()
    return render_template('admin_dashboard.html', applications=applications_list)

# Route: User Dashboard
@app.route('/user_dashboard')
def user_dashboard():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))

    user_applications = applications.find({'username': session['username']})
    return render_template('user_dashboard.html', applications=user_applications)

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

        # Allow only image files
        if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            flash('Invalid file type. Please upload an image.', 'danger')
            return redirect(request.url)

        if file:
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            extracted_text, errors = detect_document_content(file_path)

            if errors:
                flash(f"Document errors: {', '.join(errors)}", 'danger')
            else:
                flash(f"Document processed successfully: {extracted_text}", 'success')

                # Save the application details
                applications.insert_one({
                    'username': session['username'],
                    'document': file.filename,
                    'status': 'pending',
                    'timestamp': time.time()
                })

            return redirect(url_for('user_dashboard'))

    return render_template('upload.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Main entry point
if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
