from flask import Flask, request, jsonify, redirect, url_for, render_template
import os
import pytesseract
from PIL import Image
from werkzeug.utils import secure_filename
import re

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
uploaded_docs = []  # Simulating a database for uploaded documents

# Tesseract Path (Windows Users)
# Uncomment and change the path for Windows users:
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Function for OCR verification using pytesseract
def ocr_verification(file_path):
    try:
        img = Image.open(file_path)
        text = pytesseract.image_to_string(img)
        if not text.strip():
            raise ValueError("No text detected in the document")
        return text
    except Exception as e:
        print(f"OCR Processing Error: {e}")
        return None

# Aadhar number pattern
def is_valid_aadhar(text):
    pattern = r'\b[2-9]{1}[0-9]{3}[0-9]{4}[0-9]{4}\b'
    return bool(re.search(pattern, text))

# PAN card number pattern
def is_valid_pan(text):
    pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
    return bool(re.search(pattern, text))

# Function for duplicate detection
def check_duplicate(file_name):
    return file_name in uploaded_docs

# Function for expiry check (Simulating expiry for documents)
def check_expiry(text):
    # Simulate expiry check based on text
    return False  # Placeholder: Assume document is not expired

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process-application', methods=['POST'])
def process_application():
    if 'identityProof' not in request.files or 'addressProof' not in request.files:
        return redirect(url_for('result', status='error', message='Files missing'))

    identity_file = request.files['identityProof']
    address_file = request.files['addressProof']

    if identity_file.filename == '' or address_file.filename == '':
        return redirect(url_for('result', status='error', message='No selected file'))

    # Save the files
    identity_filename = secure_filename(identity_file.filename)
    identity_path = os.path.join(app.config['UPLOAD_FOLDER'], identity_filename)
    identity_file.save(identity_path)

    address_filename = secure_filename(address_file.filename)
    address_path = os.path.join(app.config['UPLOAD_FOLDER'], address_filename)
    address_file.save(address_path)

    # Run OCR on the uploaded file
    ocr_text = ocr_verification(identity_path)
    if ocr_text is None:
        return redirect(url_for('result', status='error', message='Error in OCR processing'))

    # Validate Aadhar/PAN from OCR text
    if is_valid_aadhar(ocr_text):
        doc_type = "Aadhar"
    elif is_valid_pan(ocr_text):
        doc_type = "PAN"
    else:
        return redirect(url_for('result', status='error', message='Invalid document detected'))

    # Duplicate Check
    if check_duplicate(identity_filename):
        return redirect(url_for('result', status='error', message='Duplicate document detected'))
    else:
        uploaded_docs.append(identity_filename)  # Simulate storing the document

    # Expiry Check
    if check_expiry(ocr_text):
        return redirect(url_for('result', status='error', message='Document is expired'))

    return redirect(url_for('result', status='success', message='Documents verified successfully'))

@app.route('/result')
def result():
    status = request.args.get('status')
    message = request.args.get('message')
    return render_template('result.html', status=status, message=message)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
