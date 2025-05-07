# Secure Messaging System

A secure messaging system that allows users to send encrypted messages and files with time-locked access. The system uses public key cryptography for message encryption and implements secure session management.

## Features

- User authentication with secure password management
- Encrypted message sending (text and files)
- Time-locked message access
- Secure session management
- File upload support
- Password change functionality
- Message retrieval system

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- OpenSSL (for SSL/TLS support)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install flask
```

## Configuration

1. Generate SSL certificates for secure communication:
```bash
# Generate server certificate
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365
```

2. Place the certificates in the project root directory:
- `server.crt`
- `server.key`

## Running the Application

1. Start the server:
```bash
python server.py
```

2. In a separate terminal, start the web application:
```bash
python app.py
```

The web application will be available at `http://localhost:5050`

## Usage

1. Create an account:
   - Navigate to the login page
   - Click "Create new account"
   - Follow the registration process

2. Login:
   - Enter your username and password
   - You'll be redirected to the dashboard upon successful login

3. Send a message:
   - Choose between text message or file upload
   - Enter recipient's username
   - Set the unlock date (DD:MM:YYYY:HH:MM:SS)
   - Click "Send Message"

4. Retrieve messages:
   - Click "View Messages" in the dashboard
   - Messages will be displayed if they're past their unlock date

5. Change password:
   - Click "Change Password" in the dashboard
   - Enter current and new password
   - Submit to update

## Security Features

- Session management with automatic expiration (15 minutes)
- HTTP-only cookies
- CSRF protection
- Secure password storage
- Encrypted message transmission
- Time-locked message access

## Development Notes

This is a Proof of Concept (POC) implementation. For production use, consider:

1. Moving configuration to environment variables
2. Implementing a more robust session management system
3. Adding rate limiting
4. Implementing proper error handling
5. Adding logging
6. Setting up proper HTTPS configuration

## Project Structure

```
.
├── app.py              # Web application
├── server.py           # Backend server
├── client.py           # Client utilities
├── server.crt          # SSL certificate
├── server.key          # SSL private key
└── templates/          # HTML templates
    ├── login.html
    ├── dashboard.html
    ├── send_message.html
    └── ...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Add your license information here]

## Contact

[Add your contact information here]
