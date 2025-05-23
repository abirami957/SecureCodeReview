import os
import pickle
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials
password = "supersecret123"
api_key = "ABCDEFG123456"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password_input = request.form['password']
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_input}'"
    
    # Command injection vulnerability
    os.system(f"echo {username} >> log.txt")
    
    return "Logged in!"

# Unsafe deserialization
def load_data():
    with open('data.pickle', 'rb') as f:
        return pickle.load(f)

# XSS vulnerability
@app.route('/profile')
def profile():
    user_input = request.args.get('name', '')
    return f"<h1>Welcome {user_input}</h1>"

# Insecure SSL
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_NONE

# Directory traversal
with open('../secrets.txt') as f:
    secret = f.read()