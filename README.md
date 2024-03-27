# Secure Password Manager

Secure Password Manager is a Python-based application designed to securely store and manage your passwords. Utilizing advanced encryption standards, including AES for password encryption and scrypt for key derivation, this tool ensures your passwords are safe. Additionally, it features password strength verification to encourage strong, unique passwords for every account.

## Features

- Securely encrypt and store passwords.
- Generate strong passwords.
- Verify the strength of user-created passwords.
- Manage passwords for multiple accounts and websites.
- User authentication with encrypted master passwords.
- Copy passwords to clipboard without displaying them on-screen.

## Installation

1. **Clone the Repository**

```bash
git clone <repository-url>
cd <repository-name>
```

2. **Install Dependencies**

Ensure you have Python installed on your machine. Then, install the required Python packages:

```bash
pip install pyperclip pycryptodome prettytable
```

3. **Initialize the Application**

Simply run the main script to start the application. It will initialize the database on the first run:

```bash
python password_manager.py
```

## Usage

Upon launching, the application offers three options:

- **Register:** Create a new user account with a master password.
- **Login:** Access your stored passwords using your username and master password.
- **Exit:** Quit the application.

### Managing Passwords

After logging in, you can:

- **Add** a new password.
- **Update** an existing password.
- **Delete** a stored password.
- **Copy** a password to the clipboard.
- **List** all stored passwords for your account.

## Security

- Passwords are encrypted using AES-256-CBC.
- Key derivation is performed using scrypt or PBKDF2, incorporating a unique device secret for additional security.
- The master password is hashed and stored securely.

## Dependencies

- Python 3.x
- [PyCryptodome](https://www.pycryptodome.org/)
- [Pyperclip](https://pypi.org/project/pyperclip/)
- [PrettyTable](https://pypi.org/project/prettytable/)
