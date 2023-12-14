from flask import request, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import re

# from backendAPI import readConnect, writeConnect
# Can't import due to circular import

#returns a connection with the master account
#remove in final version and replace with some account that only has permission to make, delete, and update table entries in the officehours db
def connect():
    return psycopg2.connect(
        host = "database-1.cbvvlg2e7uis.us-east-2.rds.amazonaws.com",
        database = "office-hours",
        user = "fivestar",
        password = "O6OKCxDLB4Ij2zETe2Al")

#returns a read only connection to the database
# DO LATER
def readConnect():
    return connect().cursor()

#returns a writable connection to the database
# DO LATER
#not sure how to implement, is it pretty much just only access to the office-hours database+no ability to make/delete tables?
def writeConnect():
    return connect()

# returns a string of 60 zeros separated by commas
def stringEmptySchedule():
    string = "0"
    for i in range(59):
        string += ",0"
    return string

#checks if some object exists in a table
# table: string, the table to look in
# where: string, the condition to specify the entry, format as "ATTRIBUTE=VALUE" or "ATT1=VAL1 and ATT2=VAL2"
def checkExists(table, where):
    cur = readConnect()
    cur.execute("select * from " + table + " where " + where + ";")
    if(cur.fetchone() == None):
        return False
    return True

#adds a user to the databases
# returns 0 on success
# returns -1 on failure due to email in use
def addUser(email, password, role):
    if(checkExists("users", "email='" + email + "'")):
        return -1
    con = writeConnect()
    cur = con.cursor()
    cur.execute("insert into users values ('" + email + "','" + password + "',''," + str(role) + ");")
    cur.execute("insert into userschedule values ('" + email + "'," + stringEmptySchedule() + ");")
    con.commit()
    return 0

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

# @login_manager.unauthorized_handler()
# def unauthorized_handler():
#     return {"error":'Unauthorized'}, 401

# Function to register a new user
def register_user(email, password, is_teacher):

    if not is_valid_umass_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    valid, message = validate_password(password)
    if not valid:
        return jsonify({"error": message}), 400


    # role = True if is_teacher.lower() == 'true' else False
    # role = is_teacher

    hashed_password = generate_password_hash(password)
    try:
        # con = writeConnect()
        # cur = con.cursor()
        # #cur.execute("INSERT INTO users (email, password, role) VALUES (%s, %s, %s);", (email, hashed_password, role))
        # # cur.execute("INSERT INTO users VALUES ('" + email + "','" + hashed_password + "',''," + str(is_teacher) + ");")
        # con.commit()
    if checkExists("users", "email='" + email + "'"):
        return jsonify({"error": "Email already in use"}), 409
    addUser(email, hashed_password, is_teacher)
    user = User()
    user.id = email
    login_user(user)
    return jsonify({"message": "User registered successfully"})

# Login function
def login(req):
    # req = request.get_json()
    email = req.get('email')
    password = req.get('password')

    cur = readConnect()
    cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
    user_record = cur.fetchone()

    if user_record and check_password_hash(user_record[1], password):
        user = User()
        user.id = email
        login_user(user)
        session.permanent = True
        return jsonify({"status": "logged in", "role": user_record[3]})
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

    #if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
    #    return False, "Password must include special characters."
    SPECIAL_CHARS = ["[", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", ",", ".", "?", "\"", ":", "{", "}", "|", "<", ">", "]"]
    find = False
    for i in range(len(SPECIAL_CHARS)):
        if(-1 < password.find(SPECIAL_CHARS[i])):
            find = True
            break
    if(not find):
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
