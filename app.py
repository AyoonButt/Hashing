# Cryptographic Web Service
# app.py - Main Application File

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
import hashlib
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import base64
from datetime import datetime
import io

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto_service.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship to keys
    keys = db.relationship('Key', backref='owner', lazy=True)
    files = db.relationship('File', backref='owner', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_type = db.Column(db.String(50), nullable=False)  # symmetric, public, private
    key_algorithm = db.Column(db.String(50), nullable=False)  # AES, 3DES, RSA, etc.
    key_size = db.Column(db.Integer)  # 128, 192, 256, 1024, 2048, etc.
    key_data = db.Column(db.Text, nullable=False)  # Base64 encoded key
    iv = db.Column(db.Text)  # Base64 encoded IV for symmetric ciphers
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(50))  # original, encrypted, decrypted, hashed
    file_path = db.Column(db.String(200), nullable=False)
    encryption_type = db.Column(db.String(50))  # AES, 3DES, RSA, etc.
    hash_value = db.Column(db.String(200))  # For hashed files
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Cryptographic functions
def generate_symmetric_key(algorithm, key_size):
    """Generate a symmetric key for AES or 3DES"""
    if algorithm == 'AES':
        key = get_random_bytes(key_size // 8)
        iv = get_random_bytes(16)  # AES block size is 16 bytes
        return key, iv
    elif algorithm == '3DES':
        key = DES3.adjust_key_parity(get_random_bytes(24))  # 3DES uses 24 bytes (192 bits)
        iv = get_random_bytes(8)  # 3DES block size is 8 bytes
        return key, iv
    else:
        raise ValueError("Unsupported algorithm")

def generate_rsa_keypair(key_size):
    """Generate an RSA key pair"""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file_symmetric(file_data, key, iv, algorithm, mode):
    """Encrypt file using symmetric encryption (AES or 3DES)"""
    if algorithm == 'AES':
        if mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode == 'CFB':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        else:
            raise ValueError("Unsupported mode")
        
        # Pad data to block size for CBC mode
        if mode == 'CBC':
            padded_data = pad(file_data, AES.block_size)
        else:
            padded_data = file_data
            
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data
        
    elif algorithm == '3DES':
        if mode == 'CBC':
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
        elif mode == 'CFB':
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
        else:
            raise ValueError("Unsupported mode")
        
        # Pad data to block size for CBC mode
        if mode == 'CBC':
            padded_data = pad(file_data, DES3.block_size)
        else:
            padded_data = file_data
            
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data
    else:
        raise ValueError("Unsupported algorithm")

def decrypt_file_symmetric(file_data, key, iv, algorithm, mode):
    """Decrypt file using symmetric encryption (AES or 3DES)"""
    if algorithm == 'AES':
        if mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode == 'CFB':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        else:
            raise ValueError("Unsupported mode")
        
        decrypted_data = cipher.decrypt(file_data)
        
        # Unpad data for CBC mode
        if mode == 'CBC':
            try:
                decrypted_data = unpad(decrypted_data, AES.block_size)
            except ValueError:
                # In case padding was incorrect
                pass
                
        return decrypted_data
        
    elif algorithm == '3DES':
        if mode == 'CBC':
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
        elif mode == 'CFB':
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
        else:
            raise ValueError("Unsupported mode")
        
        decrypted_data = cipher.decrypt(file_data)
        
        # Unpad data for CBC mode
        if mode == 'CBC':
            try:
                decrypted_data = unpad(decrypted_data, DES3.block_size)
            except ValueError:
                # In case padding was incorrect
                pass
                
        return decrypted_data
    else:
        raise ValueError("Unsupported algorithm")

def encrypt_file_asymmetric(file_data, public_key):
    """Encrypt file using RSA public key"""
    # Load the public key
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    
    # RSA can only encrypt small chunks of data, so we encrypt a random AES key
    # and then encrypt the file with AES
    session_key = get_random_bytes(16)
    encrypted_session_key = cipher.encrypt(session_key)
    
    # Use the session key to encrypt the file with AES
    aes_cipher = AES.new(session_key, AES.MODE_CFB, iv=get_random_bytes(16))
    encrypted_data = aes_cipher.encrypt(file_data)
    
    # Return the encrypted session key, IV, and encrypted data
    return {
        'encrypted_session_key': encrypted_session_key,
        'iv': aes_cipher.iv,
        'encrypted_data': encrypted_data
    }

def decrypt_file_asymmetric(encrypted_package, private_key):
    """Decrypt file using RSA private key"""
    # Unpack the encrypted package
    encrypted_session_key = encrypted_package['encrypted_session_key']
    iv = encrypted_package['iv']
    encrypted_data = encrypted_package['encrypted_data']
    
    # Load the private key
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    
    # Decrypt the session key
    session_key = cipher.decrypt(encrypted_session_key)
    
    # Use the session key to decrypt the file with AES
    aes_cipher = AES.new(session_key, AES.MODE_CFB, iv=iv)
    decrypted_data = aes_cipher.decrypt(encrypted_data)
    
    return decrypted_data

def hash_file(file_data, algorithm):
    """Hash a file using SHA-256 or SHA-3"""
    if algorithm == 'SHA-256':
        hash_obj = hashlib.sha256(file_data)
        return hash_obj.hexdigest()
    elif algorithm == 'SHA-3':
        hash_obj = hashlib.sha3_256(file_data)
        return hash_obj.hexdigest()
    else:
        raise ValueError("Unsupported algorithm")

def generate_secure_password(length=16):
    """Generate a secure random password"""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Check if email exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Retrieve user's keys and files
    user_keys = Key.query.filter_by(user_id=current_user.id).all()
    user_files = File.query.filter_by(user_id=current_user.id).all()
    
    return render_template('dashboard.html', 
                          user=current_user, 
                          keys=user_keys, 
                          files=user_files)

@app.route('/generate_password')
@login_required
def generate_password_route():
    password = generate_secure_password()
    return render_template('password_result.html', password=password)

@app.route('/generate_key', methods=['GET', 'POST'])
@login_required
def generate_key():
    if request.method == 'POST':
        key_name = request.form.get('key_name')
        key_type = request.form.get('key_type')
        key_algorithm = request.form.get('key_algorithm')
        key_size = int(request.form.get('key_size'))
        
        if key_type == 'symmetric':
            if key_algorithm in ['AES', '3DES']:
                key_data, iv = generate_symmetric_key(key_algorithm, key_size)
                
                # Store the key in the database
                new_key = Key(
                    name=key_name,
                    key_type=key_type,
                    key_algorithm=key_algorithm,
                    key_size=key_size,
                    key_data=base64.b64encode(key_data).decode('utf-8'),
                    iv=base64.b64encode(iv).decode('utf-8'),
                    user_id=current_user.id
                )
                
                db.session.add(new_key)
                db.session.commit()
                
                flash(f'{key_algorithm} key generated successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Unsupported algorithm', 'danger')
                
        elif key_type == 'asymmetric':
            if key_algorithm == 'RSA':
                private_key, public_key = generate_rsa_keypair(key_size)
                
                # Store the private key
                private_key_db = Key(
                    name=f"{key_name} (Private)",
                    key_type='private',
                    key_algorithm=key_algorithm,
                    key_size=key_size,
                    key_data=private_key.decode('utf-8'),
                    user_id=current_user.id
                )
                
                # Store the public key
                public_key_db = Key(
                    name=f"{key_name} (Public)",
                    key_type='public',
                    key_algorithm=key_algorithm,
                    key_size=key_size,
                    key_data=public_key.decode('utf-8'),
                    user_id=current_user.id
                )
                
                db.session.add(private_key_db)
                db.session.add(public_key_db)
                db.session.commit()
                
                flash('RSA key pair generated successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Unsupported algorithm', 'danger')
        else:
            flash('Invalid key type', 'danger')
            
    return render_template('generate_key.html')

@app.route('/encrypt_file', methods=['GET', 'POST'])
@login_required
def encrypt_file():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        encryption_type = request.form.get('encryption_type')
        
        if encryption_type == 'symmetric':
            key_id = request.form.get('symmetric_key_id')
            mode = request.form.get('block_mode')
            
            # Get the key from the database
            key_obj = Key.query.get(key_id)
            
            if not key_obj or key_obj.user_id != current_user.id:
                flash('Invalid key', 'danger')
                return redirect(request.url)
                
            # Read the file data
            file_data = file.read()
            
            # Decrypt the key and IV from base64
            key_data = base64.b64decode(key_obj.key_data)
            iv = base64.b64decode(key_obj.iv)
            
            try:
                # Encrypt the file
                encrypted_data = encrypt_file_symmetric(file_data, key_data, iv, key_obj.key_algorithm, mode)
                
                # Save the encrypted file
                encrypted_filename = secure_filename(f"encrypted_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
                
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Save file information to database
                new_file = File(
                    filename=encrypted_filename,
                    file_type='encrypted',
                    file_path=file_path,
                    encryption_type=f"{key_obj.key_algorithm}-{mode}",
                    user_id=current_user.id,
                    key_id=key_obj.id
                )
                
                db.session.add(new_file)
                db.session.commit()
                
                flash('File encrypted successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f'Encryption failed: {str(e)}', 'danger')
                return redirect(request.url)
                
        elif encryption_type == 'asymmetric':
            key_id = request.form.get('asymmetric_key_id')
            
            # Get the key from the database
            key_obj = Key.query.get(key_id)
            
            if not key_obj or key_obj.user_id != current_user.id or key_obj.key_type != 'public':
                flash('Invalid key', 'danger')
                return redirect(request.url)
                
            # Read the file data
            file_data = file.read()
            
            try:
                # Encrypt the file
                encrypted_package = encrypt_file_asymmetric(file_data, key_obj.key_data.encode('utf-8'))
                
                # Save the encrypted package
                encrypted_filename = secure_filename(f"encrypted_{file.filename}.pkg")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
                
                # Save the package as a binary file
                with open(file_path, 'wb') as f:
                    # Write the encrypted session key size
                    f.write(len(encrypted_package['encrypted_session_key']).to_bytes(4, byteorder='big'))
                    # Write the encrypted session key
                    f.write(encrypted_package['encrypted_session_key'])
                    # Write the IV
                    f.write(encrypted_package['iv'])
                    # Write the encrypted data
                    f.write(encrypted_package['encrypted_data'])
                
                # Save file information to database
                new_file = File(
                    filename=encrypted_filename,
                    file_type='encrypted',
                    file_path=file_path,
                    encryption_type=f"{key_obj.key_algorithm}-asymmetric",
                    user_id=current_user.id,
                    key_id=key_obj.id
                )
                
                db.session.add(new_file)
                db.session.commit()
                
                flash('File encrypted successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f'Encryption failed: {str(e)}', 'danger')
                return redirect(request.url)
        else:
            flash('Invalid encryption type', 'danger')
            return redirect(request.url)
            
    # Get user's keys for the form
    symmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='symmetric').all()
    public_keys = Key.query.filter_by(user_id=current_user.id, key_type='public').all()
    
    return render_template('encrypt_file.html', 
                          symmetric_keys=symmetric_keys, 
                          public_keys=public_keys)

@app.route('/decrypt_file', methods=['GET', 'POST'])
@login_required
def decrypt_file():
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        key_id = request.form.get('key_id')
        
        # Get the file from the database
        file_obj = File.query.get(file_id)
        
        if not file_obj or file_obj.user_id != current_user.id:
            flash('Invalid file', 'danger')
            return redirect(request.url)
            
        # Get the key from the database
        key_obj = Key.query.get(key_id)
        
        if not key_obj or key_obj.user_id != current_user.id:
            flash('Invalid key', 'danger')
            return redirect(request.url)
            
        # Read the encrypted file
        with open(file_obj.file_path, 'rb') as f:
            encrypted_data = f.read()
            
        try:
            # Check encryption type to choose decryption method
            if 'asymmetric' in file_obj.encryption_type:
                # This is an asymmetric encrypted file package
                
                # Make sure we're using the right key
                if key_obj.key_type != 'private':
                    flash('Asymmetric decryption requires a private key', 'danger')
                    return redirect(request.url)
                    
                # Parse the package
                with open(file_obj.file_path, 'rb') as f:
                    # Read the encrypted session key size
                    session_key_size = int.from_bytes(f.read(4), byteorder='big')
                    # Read the encrypted session key
                    encrypted_session_key = f.read(session_key_size)
                    # Read the IV (16 bytes for AES)
                    iv = f.read(16)
                    # Read the encrypted data
                    encrypted_data = f.read()
                
                encrypted_package = {
                    'encrypted_session_key': encrypted_session_key,
                    'iv': iv,
                    'encrypted_data': encrypted_data
                }
                
                # Decrypt the file
                decrypted_data = decrypt_file_asymmetric(encrypted_package, key_obj.key_data.encode('utf-8'))
                
            else:
                # This is a symmetric encrypted file
                
                # Make sure we're using the right key
                if key_obj.key_type != 'symmetric':
                    flash('Symmetric decryption requires a symmetric key', 'danger')
                    return redirect(request.url)
                    
                # Parse encryption type to get algorithm and mode
                algorithm, mode = file_obj.encryption_type.split('-')
                
                # Decrypt the key and IV from base64
                key_data = base64.b64decode(key_obj.key_data)
                iv = base64.b64decode(key_obj.iv)
                
                # Decrypt the file
                decrypted_data = decrypt_file_symmetric(encrypted_data, key_data, iv, algorithm, mode)
            
            # Create a decrypted filename
            if file_obj.filename.startswith('encrypted_'):
                decrypted_filename = file_obj.filename[10:]  # Remove 'encrypted_' prefix
            else:
                decrypted_filename = f"decrypted_{file_obj.filename}"
                
            if decrypted_filename.endswith('.pkg'):
                decrypted_filename = decrypted_filename[:-4]  # Remove .pkg suffix
                
            # Save the decrypted file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(decrypted_filename))
            
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Save file information to database
            new_file = File(
                filename=decrypted_filename,
                file_type='decrypted',
                file_path=file_path,
                encryption_type=file_obj.encryption_type,
                user_id=current_user.id,
                key_id=key_obj.id
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            flash('File decrypted successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'danger')
            return redirect(request.url)
    
    # Get user's encrypted files and keys for the form
    encrypted_files = File.query.filter_by(user_id=current_user.id, file_type='encrypted').all()
    symmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='symmetric').all()
    private_keys = Key.query.filter_by(user_id=current_user.id, key_type='private').all()
    
    return render_template('decrypt_file.html', 
                          encrypted_files=encrypted_files, 
                          symmetric_keys=symmetric_keys, 
                          private_keys=private_keys)

@app.route('/hash_file', methods=['GET', 'POST'])
@login_required
def hash_file_route():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        hash_algorithm = request.form.get('hash_algorithm')
        
        # Read the file data
        file_data = file.read()
        
        try:
            # Hash the file
            hash_value = hash_file(file_data, hash_algorithm)
            
            # Save the original file
            original_filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
            
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Save file information to database
            new_file = File(
                filename=original_filename,
                file_type='hashed',
                file_path=file_path,
                encryption_type=hash_algorithm,
                hash_value=hash_value,
                user_id=current_user.id
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            flash(f'File hashed successfully! Hash: {hash_value}', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Hashing failed: {str(e)}', 'danger')
            return redirect(request.url)
            
    return render_template('hash_file.html')

@app.route('/compare_hash', methods=['GET', 'POST'])
@login_required
def compare_hash():
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        # Get the stored file from the database
        stored_file = File.query.get(file_id)
        
        if not stored_file or stored_file.user_id != current_user.id or stored_file.file_type != 'hashed':
            flash('Invalid file', 'danger')
            return redirect(request.url)
            
        # Read the uploaded file data
        file_data = file.read()
        
        try:
            # Hash the uploaded file with the same algorithm
            hash_value = hash_file(file_data, stored_file.encryption_type)
            
            # Compare hashes
            if hash_value == stored_file.hash_value:
                flash('Hashes match! Files are identical.', 'success')
            else:
                flash('Hashes do not match! Files are different.', 'warning')
                
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Hash comparison failed: {str(e)}', 'danger')
            return redirect(request.url)
    
    # Get user's hashed files for the form
    hashed_files = File.query.filter_by(user_id=current_user.id, file_type='hashed').all()
    
    return render_template('compare_hash.html', hashed_files=hashed_files)

@app.route('/download_file/<int:file_id>')
@login_required
def download_file(file_id):
    file_obj = File.query.get(file_id)
    
    if not file_obj or file_obj.user_id != current_user.id:
        flash('Invalid file', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        return send_file(file_obj.file_path, as_attachment=True, download_name=file_obj.filename)
    except Exception as e:
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/download_key/<int:key_id>')
@login_required
def download_key(key_id):
    key_obj = Key.query.get(key_id)
    
    if not key_obj or key_obj.user_id != current_user.id:
        flash('Invalid key', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Create a temporary file to hold the key data
        key_data = key_obj.key_data
        
        # If it's a symmetric key, also include the IV
        if key_obj.key_type == 'symmetric':
            key_data += f"\nIV: {key_obj.iv}"
        
        # Create a downloadable file
        key_file = io.BytesIO(key_data.encode('utf-8'))
        
        # Create a filename based on key information
        filename = f"{key_obj.name}_{key_obj.key_algorithm}_{key_obj.key_size}.key"
        
        return send_file(key_file, as_attachment=True, download_name=filename, mimetype='text/plain')
        
    except Exception as e:
        flash(f'Key download failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        # Save the file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Save file information to database
        new_file = File(
            filename=filename,
            file_type='original',
            file_path=file_path,
            user_id=current_user.id
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
            
    return render_template('upload_file.html')

@app.route('/upload_key', methods=['GET', 'POST'])
@login_required
def upload_key():
    if request.method == 'POST':
        key_name = request.form.get('key_name')
        key_type = request.form.get('key_type')
        key_algorithm = request.form.get('key_algorithm')
        key_size = int(request.form.get('key_size'))
        
        # Check if key file was uploaded
        if 'key_file' not in request.files:
            flash('No key file selected', 'danger')
            return redirect(request.url)
            
        key_file = request.files['key_file']
        
        # Check if key file was selected
        if key_file.filename == '':
            flash('No key file selected', 'danger')
            return redirect(request.url)
            
        # Read key data
        key_data = key_file.read().decode('utf-8')
        
        # For symmetric keys, handle IV
        iv = None
        if key_type == 'symmetric':
            # Check if IV was uploaded
            if 'iv_file' not in request.files:
                flash('No IV file selected for symmetric key', 'danger')
                return redirect(request.url)
                
            iv_file = request.files['iv_file']
            
            # Check if IV file was selected
            if iv_file.filename == '':
                flash('No IV file selected for symmetric key', 'danger')
                return redirect(request.url)
                
            # Read IV data
            iv = iv_file.read().decode('utf-8')
        
        # Store the key in the database
        new_key = Key(
            name=key_name,
            key_type=key_type,
            key_algorithm=key_algorithm,
            key_size=key_size,
            key_data=key_data,
            iv=iv,
            user_id=current_user.id
        )
        
        db.session.add(new_key)
        db.session.commit()
        
        flash('Key uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
            
    return render_template('upload_key.html')

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Check if current password is correct
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('account'))
                
            # Check if new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('account'))
                
            # Update password
            current_user.set_password(new_password)
            db.session.commit()
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        elif action == 'update_email':
            new_email = request.form.get('new_email')
            
            # Check if email exists
            existing_email = User.query.filter_by(email=new_email).first()
            if existing_email and existing_email.id != current_user.id:
                flash('Email already exists', 'danger')
                return redirect(url_for('account'))
                
            # Update email
            current_user.email = new_email
            db.session.commit()
            
            flash('Email updated successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        elif action == 'delete_account':
            password = request.form.get('delete_password')
            
            # Check if password is correct
            if not current_user.check_password(password):
                flash('Password is incorrect', 'danger')
                return redirect(url_for('account'))
                
            # Delete user's files
            for file in current_user.files:
                try:
                    os.remove(file.file_path)
                except:
                    pass
                    
            # Delete user's data from database
            File.query.filter_by(user_id=current_user.id).delete()
            Key.query.filter_by(user_id=current_user.id).delete()
            
            # Get user ID for deletion after logout
            user_id = current_user.id
            
            # Log out the user
            logout_user()
            
            # Delete the user
            User.query.filter_by(id=user_id).delete()
            db.session.commit()
            
            flash('Your account has been deleted', 'info')
            return redirect(url_for('index'))
            
    return render_template('account.html', user=current_user)

@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    file_obj = File.query.get(file_id)
    
    if not file_obj or file_obj.user_id != current_user.id:
        flash('Invalid file', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        # Delete the file from the filesystem
        os.remove(file_obj.file_path)
    except:
        pass
        
    # Delete the file from the database
    db.session.delete(file_obj)
    db.session.commit()
    
    flash('File deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_key/<int:key_id>')
@login_required
def delete_key(key_id):
    key_obj = Key.query.get(key_id)
    
    if not key_obj or key_obj.user_id != current_user.id:
        flash('Invalid key', 'danger')
        return redirect(url_for('dashboard'))
        
    # Delete the key from the database
    db.session.delete(key_obj)
    db.session.commit()
    
    flash('Key deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

# Create admin user if it doesn't exist# Replace the before_first_request with this
with app.app_context():
    db.create_all()  # Create database tables
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user
        admin = User(username='admin', email='admin@example.com')
        admin.set_password('admin')  # Change this in production!
        
        db.session.add(admin)
        db.session.commit()

# Run the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)