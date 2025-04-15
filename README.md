# Cryptographic Web Service

A secure web application for cryptographic operations built with Python and Flask. This application allows users to encrypt, decrypt, hash files, and manage cryptographic keys through a user-friendly web interface.

## Features

- User authentication system
- File upload and management
- Symmetric encryption (AES and 3DES)
- Asymmetric encryption (RSA)
- File hashing (SHA-256 and SHA-3)
- Key generation and management
- Secure password generation

## Supported Cryptographic Methods

### Encryption
- 3DES (Triple DES)
- AES (128-bit, 192-bit, and 256-bit)
- RSA (1024-bit, 2048-bit, and 4096-bit)

### Block Modes
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)

### Secure Hashing
- SHA-256
- SHA-3

### Key Generation
- Symmetric keys (AES, 3DES)
- Asymmetric key pairs (RSA)
- Secure password generation

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/crypto-web-service.git
cd crypto-web-service
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```
pip install -r requirements.txt
```

4. Run the application:
```
python app.py
```

5. Access the application in your web browser at `http://127.0.0.1:5000`

## Default Admin Account

The application creates a default admin account on first run:
- Username: admin
- Password: admin

**Important:** Change the default admin password immediately after first login for security reasons.

## Project Structure

- `app.py`: Main application file
- `templates/`: HTML templates for the web interface
- `uploads/`: Directory for uploaded and processed files
- `requirements.txt`: List of required Python packages

## Security Notes

- All user passwords are hashed before storage
- Files are stored securely with unique identifiers
- Keys are stored as base64-encoded strings in the database
- For production deployment, additional security measures should be implemented:
  - Use HTTPS
  - Configure proper session management
  - Set up database backups
  - Implement rate limiting
  - Consider using a production-ready web server like Gunicorn with Nginx

## License

This project is licensed under the MIT License - see the LICENSE file for details.
