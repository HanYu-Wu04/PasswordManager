from binascii import unhexlify
import sqlite3
import os
import argparse
import pyperclip
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt, PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from prettytable import PrettyTable
import json
import secrets
import string
from getpass import getpass
import re

def is_strong_password(password, username):
    if len(password) < 12:
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    if username in password:
        return False
    return True

def get_valid_master_password(username):
    print("The master password should be at least 12 characters long, contains at least 1 number, 1 lowercase, 1 uppercase, and 1 special character")
    while True:
        master_password = getpass("Create a master password: ")
        if is_strong_password(master_password, username):
            return master_password
        else:
            print("The master password does not meet the requirements.")


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def update_password(user_id, website, username, encrypted_password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("UPDATE passwords SET password = ? WHERE user_id = ? AND website = ? AND username = ?",
              (encrypted_password, user_id, website, username))
    conn.commit()
    conn.close()

def delete_password(user_id, website, username):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE user_id = ? AND website = ? AND username = ?",
              (user_id, website, username))
    conn.commit()
    conn.close()

# Generates or reads the device secret
def get_or_create_device_secret():
    secret_path = 'device_secret.json'
    try:
        with open(secret_path, 'r') as file:
            data = json.load(file)
            return data['device_secret']
    except FileNotFoundError:
        device_secret = get_random_bytes(16).hex()  # Generate a new device secret
        with open(secret_path, 'w') as file:
            json.dump({'device_secret': device_secret}, file)
        return device_secret

device_secret = get_or_create_device_secret()

# Derives encryption key using master password and device secret
def derive_key(password, salt):
    if isinstance(password, str):
        password = password.encode()
    
    device_secret_bytes = unhexlify(device_secret)
    combined = password + device_secret_bytes  # password is a byte, device_secret_bytes is bytes
    print("Debug: Deriving key with combined inputs.")
    return scrypt(combined, salt, 32, N=2**14, r=8, p=1)


def encrypt_password(password, master_password):
    salt = get_random_bytes(16)
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(password.encode(), AES.block_size))
    print(f"Debug: Encrypting password, salt={salt.hex()}, key={key.hex()}")
    return salt + cipher.iv + ct_bytes

def decrypt_password(encrypted_password, master_password):
    try:
        salt = encrypted_password[:16]
        iv = encrypted_password[16:32]
        ct = encrypted_password[32:]
        key = derive_key(master_password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print(f"Debug: Decrypting password, salt={salt.hex()}, key={key.hex()}")
        return pt.decode()
    except (ValueError, KeyError) as e:
        print("Decryption failed. Possibly incorrect master password.")
        print(f"Decryption failed. Possibly incorrect master password. Error: {e}")
        return None

def initialize_database():
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password BLOB, master_password_hash BLOB)''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, user_id INTEGER, website TEXT, username TEXT, password BLOB,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

def hash_master_password(master_password):
    salt = get_random_bytes(16)
    key = PBKDF2(master_password, salt, dkLen=32, count=100000)
    return salt + key

def verify_master_password(stored_hash, master_password):
    salt = stored_hash[:16]
    original_key = stored_hash[16:]
    new_key = PBKDF2(master_password, salt, dkLen=32, count=100000)
    return new_key == original_key

def register_user():
    username = input("Username: ")
    account_password = getpass("Account Password: ")
    master_password = get_valid_master_password(username)
    master_password_hash = hash_master_password(master_password)
    encrypted_password = encrypt_password(account_password, master_password)
    try:
        conn = sqlite3.connect('password_manager.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, master_password_hash) VALUES (?, ?, ?)",
                  (username, encrypted_password, master_password_hash))
        conn.commit()
        print("User registered successfully.")
    except sqlite3.IntegrityError:
        print("User already exists. Try another username.")
    finally:
        conn.close()

def authenticate_user():
    """
    Authenticates the user without requiring the master password to be passed around.
    Returns user ID and a temporary key for session-based actions instead of the master password.
    """
    username = input("Username: ")
    master_password = getpass("Enter your master password to login: ")
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("SELECT id, master_password_hash FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if user:
        user_id, stored_hash = user
        if verify_master_password(stored_hash, master_password):
            # Generate a temporary session key using a simplified approach
            session_key = PBKDF2(master_password, stored_hash[:16], dkLen=32, count=1000)
            print(f"Welcome back, {username}!")
            del master_password  # Attempt to remove master password from memory
            return user_id, session_key
    print("Login failed. Check your username and master password.")
    return None, None

def add_password(user_id, website, username, password, master_password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    encrypted_password = encrypt_password(password, master_password)
    c.execute("INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)",
              (user_id, website, username, encrypted_password))
    conn.commit()
    conn.close()

def get_passwords(user_id, master_password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("SELECT website, username, password FROM passwords WHERE user_id=?", (user_id,))
    encrypted_passwords = c.fetchall()
    conn.close()
    decrypted_passwords = []
    for website, username, password in encrypted_passwords:
        decrypted_password = decrypt_password(password, master_password)
        if decrypted_password:
            decrypted_passwords.append((website, username, decrypted_password))
    return decrypted_passwords

# session key acts as the master password
def copy_password_to_clipboard(website, user_id, username, master_password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    try:
        # Query to fetch the encrypted password based on website, username, and user_id
        c.execute("SELECT password FROM passwords WHERE user_id=? AND website=? AND username=?", (user_id, website, username))
        password_entry = c.fetchone()

        if password_entry:
            encrypted_password = password_entry[0]
            # Attempt to decrypt the password
            decrypted_password = decrypt_password(encrypted_password, master_password)
            if decrypted_password:
                pyperclip.copy(decrypted_password)
                print(f"Password for {website} with username '{username}' copied to clipboard.")
            else:
                # If decryption fails, provide a clearer message to guide the next steps
                print("Decryption failed. Please check the master password and ensure it is correct.")
        else:
            print("No password entry found for the specified website and username.")
    except Exception as e:
        print(f"An error occurred while attempting to copy the password to the clipboard: {e}")
    finally:
        conn.close()



def verify_user(user_id, master_password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("SELECT master_password_hash FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user and verify_master_password(user[0], master_password):
        return True
    return False

def add_password_flow(user_id, session_key):
    website = input("Website: ")
    username = input("Username for the website: ")
    password = getpass("Password for the website (leave blank to generate a strong one): ")
    if not password:
        password = generate_strong_password()
        print(f"Generated password: {password}")
    encrypted_password = encrypt_password(password, session_key)  # Assuming session_key can be used directly
    save_password(user_id, website, username, encrypted_password)
    print("Password saved successfully.")

def update_password_flow(user_id, session_key):
    # Ask for the master password again for extra verification
    print("For security, please re-enter your master password.")
    master_password = getpass("Master Password: ")
    if not verify_user(user_id, master_password):
        print("Incorrect master password. Action canceled.")
        return
    
    website = input("Website to update: ")
    username = input("Username for the website: ")
    new_password = getpass("New password for the website: ")
    encrypted_password = encrypt_password(new_password, session_key)  # Assuming session_key can be used directly
    update_password(user_id, website, username, encrypted_password)
    print("Password updated successfully.")

def delete_password_flow(user_id):
    # Ask for the master password again for extra verification
    print("For security, please re-enter your master password.")
    master_password = getpass("Master Password: ")
    if not verify_user(user_id, master_password):
        print("Incorrect master password. Action canceled.")
        return
    
    website = input("Website to delete: ")
    username = input("Username for the website: ")
    delete_password(user_id, website, username)
    print("Password deleted successfully.")

def copy_password_flow(user_id, session_key):
    # Ask for the master password again for extra verification
    print("For security, please re-enter your master password.")
    master_password = getpass("Master Password: ")
    if not verify_user(user_id, master_password):
        print("Incorrect master password. Action canceled.")
        return

    website = input("Enter the website: ")
    username = input("Enter the username for the website: ")
    copy_password_to_clipboard(website, user_id, username, session_key)

def list_passwords_flow(user_id, session_key):
    # Ask for the master password again for extra verification
    print("For security, please re-enter your master password.")
    master_password = getpass("Master Password: ")
    if not verify_user(user_id, master_password):
        print("Incorrect master password. Action canceled.")
        return
    
    passwords = get_passwords(user_id, session_key)  # Assuming this decrypts passwords with the session_key
    if passwords:
        table = PrettyTable(["Website", "Username", "Password"])
        for website, username, password in passwords:
            table.add_row([website, username, password])
        print(table)
    else:
        print("No passwords stored.")

def save_password(user_id, website, username, encrypted_password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)",
              (user_id, website, username, encrypted_password))
    conn.commit()
    conn.close()

def get_password(user_id, website, session_key):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("SELECT password FROM passwords WHERE user_id=? AND website=?", (user_id, website))
    encrypted_password = c.fetchone()
    conn.close()
    if encrypted_password:
        return decrypt_password(encrypted_password[0], session_key)
    return None

def get_user_id(username):
    """Retrieve the user ID based on the username."""
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    conn.close()
    return user_id[0] if user_id else None

def user_actions(user_id, session_key):
    if not user_id:
        print("Failed to authenticate user.")
        return
    while True:
        action = input("\nAvailable actions: [add, update, delete, copy, list, exit]\nWhat would you like to do? ").strip().lower()
        if action == 'add':
            add_password_flow(user_id, session_key)
        elif action == 'update':
            update_password_flow(user_id, session_key)
        elif action == 'delete':
            delete_password_flow(user_id)
        elif action == 'copy':
            copy_password_flow(user_id, session_key)
        elif action == 'list':
            list_passwords_flow(user_id, session_key)
        elif action == 'exit':
            print("Exiting user session.")
            break
        else:
            print("Invalid action. Please choose again.")

def main_menu():
    print("Welcome to the Secure Password Manager")
    while True:
        user_choice = input("Do you want to [register], [login], or [exit]? ").strip().lower()
        if user_choice == 'register':
            register_user()
        elif user_choice == 'login':
            username, session_key = authenticate_user()
            if username and session_key:
                user_actions(username, session_key)
        elif user_choice == 'exit':
            print("Exiting the password manager.")
            break
        else:
            print("Invalid choice. Please type 'register', 'login', or 'exit'.")

if __name__ == "__main__":
    initialize_database()
    main_menu()