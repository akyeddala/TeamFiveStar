from flask import request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import re

from backendAPI import readConnect, writeConnect

# Initialize the login manager
login_manager = LoginManager()

# User class for Flask-Login
class User(UserMixin):
    pass

# User Loader for Flask-Login
@login_manager.user_loader
def user_loader(email):
    cur = readConnect()
    cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
    record = cur.fetchone()
    if record is None:
        return None

    user = User()
    user.id = email
    return user

# Function to register a new user
def register_user(email, password, is_teacher):
    
    if not is_valid_umass_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    valid, message = validate_password(password)
    if not valid:
        return jsonify({"error": message}), 400
    
    
    role = True if is_teacher.lower() == 'true' else False

    hashed_password = generate_password_hash(password)
    try:
        con = writeConnect()
        cur = con.cursor()
        cur.execute("INSERT INTO users (email, password, role) VALUES (%s, %s, %s);", (email, hashed_password, role))
        con.commit()
        return jsonify({"message": "User registered successfully"})
    except psycopg2.IntegrityError:
        return jsonify({"error": "Email already in use"}), 409

# Login function
def login():
    req = request.get_json()
    email = req.get('email')
    password = req.get('password')

    cur = readConnect()
    cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
    user_record = cur.fetchone()

    if user_record and check_password_hash(user_record[1], password):
        user = User()
        user.id = email
        login_user(user)
        return jsonify({"status": "logged in"})
    return jsonify({"status": "invalid credentials"}), 401

# Logout function
@login_required
def logout():
    logout_user()
    return jsonify({"status": "logged out"})


def validate_password(password):
    """
    Validate the given password based on certain criteria.
    Returns a tuple (bool, message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search("[a-z]", password):
        return False, "Password must include lowercase letters."

    if not re.search("[A-Z]", password):
        return False, "Password must include uppercase letters."

    if not re.search("[0-9]", password):
        return False, "Password must include numbers."

    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must include special characters."

    return True, "Password is valid."

def is_valid_umass_email(email):
    """ Validate if the email is a umass.edu email """
    pattern = r'^[\w\.-]+@umass\.edu$'
    return re.match(pattern, email) is not None

# Example Usage
email = "example@umass.edu"
if is_valid_umass_email(email):
    print("Valid UMass email")
else:
    print("Invalid UMass email")