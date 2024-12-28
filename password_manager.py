# src/password_manager.py

import getpass
import os
import secrets
import string
import hashlib
import logging
import time
from cryptography.fernet import Fernet
from pathlib import Path
import json

# Configure logging
logging.basicConfig(filename='password_manager.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to validate password complexity
def validate_password_strength(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if len(password) > 64:
        return False, "Password must be no more than 64 characters long."
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit."
    if not any(char in string.punctuation for char in password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

# Generate a key and store in an environment variable (for demonstration purposes)
def generate_key():
    key = Fernet.generate_key()
    os.environ['PASSWORD_MANAGER_KEY'] = key.decode()
    return key

# Load the key from an environment variable
def load_key():
    key = os.environ.get('PASSWORD_MANAGER_KEY')
    if key is None:
        raise ValueError("No encryption key found in environment variables.")
    return key.encode()

# Encrypt data
def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

# Decrypt data
def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

# Save passwords to an encrypted file with integrity check
def save_passwords(passwords, key):
    data = json.dumps(passwords)
    encrypted_data = encrypt_data(data, key)
    hash_data = hashlib.sha256(encrypted_data).hexdigest()
    with open("passwords.enc", "wb") as file:
        file.write(encrypted_data)
    with open("passwords.hash", "w") as hash_file:
        hash_file.write(hash_data)
    # Set file permissions to read/write for owner only
    os.chmod("passwords.enc", 0o600)
    os.chmod("passwords.hash", 0o600)

# Load passwords from an encrypted file with integrity check
def load_passwords(key):
    if not Path("passwords.enc").is_file():
        return []
    with open("passwords.enc", "rb") as file:
        encrypted_data = file.read()
    with open("passwords.hash", "r") as hash_file:
        stored_hash = hash_file.read()
    current_hash = hashlib.sha256(encrypted_data).hexdigest()
    if stored_hash != current_hash:
        raise ValueError("Data integrity check failed. The passwords file may have been tampered with.")
    decrypted_data = decrypt_data(encrypted_data, key)
    return json.loads(decrypted_data)

# Add a new password entry
def add_password(passwords, service, username, password):
    passwords.append({"service": service, "username": username, "password": password})

# Retrieve a password entry
def get_password(passwords, service):
    for entry in passwords:
        if entry["service"] == service:
            return entry["username"], entry["password"]
    return None, None

# Generate a strong password
def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    secure_password = ''.join(secrets.choice(characters) for _ in range(length))
    return secure_password

def authenticate(stored_hash):
    password_attempt = getpass.getpass("Enter master password: ").strip()
    hashed_attempt = hashlib.sha256(password_attempt.encode()).hexdigest()
    return hashed_attempt == stored_hash

def main():
    # Ensure the environment variable is set securely
    if 'PASSWORD_MANAGER_KEY' not in os.environ:
        generate_key()

    key = load_key()

    # Check if master password hash exists
    if not Path("master_password.hash").is_file():
        while True:
            master_password = getpass.getpass("Set a new master password: ").strip()
            is_strong, message = validate_password_strength(master_password)
            if is_strong:
                break
            print(message)
        stored_hash = hashlib.sha256(master_password.encode()).hexdigest()
        with open("master_password.hash", "w") as hash_file:
            hash_file.write(stored_hash)
        os.chmod("master_password.hash", 0o600)
    else:
        with open("master_password.hash", "r") as hash_file:
            stored_hash = hash_file.read()

    if not authenticate(stored_hash):
        print("Authentication failed. Exiting.")
        logging.warning("Failed authentication attempt.")
        return

    try:
        passwords = load_passwords(key)
    except ValueError as e:
        print(e)
        logging.error(e)
        return

    session_start_time = time.time()
    session_timeout = 300  # Session timeout in seconds (e.g., 5 minutes)

    while True:
        current_time = time.time()
        if current_time - session_start_time > session_timeout:
            print("Session expired. Please re-authenticate.")
            if not authenticate(stored_hash):
                print("Authentication failed. Exiting.")
                logging.warning("Failed authentication attempt during session.")
                break
            session_start_time = current_time

        choice = input("Choose an option (add/retrieve/generate/quit): ").strip().lower()
        if choice == "add":
            service = input("Enter the service name: ").strip()
            username = input("Enter the username: ").strip()
            password = getpass.getpass("Enter the password: ").strip()
            add_password(passwords, service, username, password)
            save_passwords(passwords, key)
            print("Password added successfully.")
            logging.info(f"Added password for service: {service}")
        elif choice == "retrieve":
            service = input("Enter the service name: ").strip()
            username, password = get_password(passwords, service)
            if username and password:
                print(f"Username: {username}, Password: {password}")
                logging.info(f"Retrieved password for service: {service}")
            else:
                print("No password found for the given service.")
                logging.warning(f"Failed to retrieve password for service: {service}")
        elif choice == "generate":
            length = int(input("Enter the desired length of the password: ").strip())
            strong_password = generate_strong_password(length)
            print(f"Generated strong password: {strong_password}")
            logging.info("Generated a strong password.")
        elif choice == "quit":
            break
        else:
            print("Invalid choice. Please enter add/retrieve/generate/quit.")
            logging.warning("Invalid menu choice.")

if __name__ == "__main__":
    main()
