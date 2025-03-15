from flask import Flask, request, jsonify, render_template_string
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
import hmac
import hashlib
from urllib.parse import parse_qs
import json

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'A1u3b8e0d@#'  # Replace with a secure key in production

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# MySQL database setup
def init_db():
    try:
        conn = mysql.connector.connect(
            host='miniapp',     # replace with your MySQL host
            user='root',          # replace with your MySQL username
            password='4zjqmEfeRhCqYYDhvkaODXD3',           # replace with your MySQL password
            database='elastic_brahmagupta',     # replace with your database name
        )
        if conn.is_connected():
            print('Connected to MySQL.')
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                             (id INT PRIMARY KEY AUTO_INCREMENT, 
                              bale_user_id INT UNIQUE, 
                              username TEXT)''')
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Error connecting to MySQL: {e}")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, bale_user_id, username):
        self.id = id
        self.bale_user_id = bale_user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = mysql.connector.connect(
            host='miniapp',     # replace with your MySQL host
            user='root',          # replace with your MySQL username
            password='4zjqmEfeRhCqYYDhvkaODXD3',           # replace with your MySQL password
            database='elastic_brahmagupta',     # replace with your database name
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, bale_user_id, username FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2])
        return None
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

# Bot token (replace with your actual bot token)
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"  

def url_decode(s):
    """Decode URL-encoded string with UTF-8 support"""
    bytes_list = []
    i = 0
    while i < len(s):
        if s[i] == '%':
            try:
                # Decode percent-encoded byte
                hex_code = s[i+1:i+3]
                byte_val = int(hex_code, 16)
                bytes_list.append(byte_val)
                i += 3
            except (ValueError, IndexError):
                # Invalid encoding, keep literal %
                bytes_list.append(ord('%'))
                i += 1
        elif s[i] == '+':
            # Convert '+' to space
            bytes_list.append(0x20)
            i += 1
        else:
            # Regular ASCII character
            bytes_list.append(ord(s[i]))
            i += 1
    
    # Convert bytes to UTF-8 string
    return bytes(bytes_list).decode('utf-8', errors='replace')

def parse_qs(query_string):
    """Parse a URL-encoded query string into a dictionary"""
    params = {}
    pairs = query_string.split('&')
    for pair in pairs:
        if not pair:
            continue
        parts = pair.split('=', 1)
        key = url_decode(parts[0])
        value = url_decode(parts[1]) if len(parts) > 1 else ''
        if key in params:
            # Handle repeated keys by appending to a list
            if isinstance(params[key], list):
                params[key].append(value)
            else:
                params[key] = [params[key], value]
        else:
            params[key] = value
    return params

# Your validate_init_data function
def validate_init_data(init_data):
    print(f"init_data type: {type(init_data)}")
    print(f"Raw init_data: {init_data}")
    
    # Step 1: Decode the entire string first
    decoded_init_data = url_decode(init_data)
    print(f"Decoded init_data: {decoded_init_data}")
    
    # Step 2: Parse the decoded string
    parsed_data = parse_qs(decoded_init_data)  # Use the decoded string here
    print(f"parsed_data: {parsed_data}")
    
    # Rest of your existing code...
    data_dict = {k: v[0] if isinstance(v, list) else v for k, v in parsed_data.items()}
    print(f"dict: {data_dict}")
    
    hash_value = data_dict.pop('hash', None)
    print(f"hash: {hash_value}")
    if not hash_value:
        return False, "Missing hash in initData"
    
    return True, data_dict
# Routes
@app.route('/register', methods=['POST'])
def register():
    init_data = request.get_json().get('initData')
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400
    
    is_valid, result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': result}), 400
    data_dict = result
    
    user_json = data_dict.get('user')
    if not user_json:
        return jsonify({'error': 'Missing user data'}), 400
    try:
        user_data = json.loads(user_json)
        bale_user_id = user_data['id']
        username = user_data.get('username', '')
    except (json.JSONDecodeError, KeyError):
        return jsonify({'error': 'Invalid user data'}), 400
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='users'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE bale_user_id = %s", (bale_user_id,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
        
        cursor.execute("INSERT INTO users (bale_user_id, username) VALUES (%s, %s)", 
                      (bale_user_id, username))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    init_data = request.get_json().get('initData')
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400
    
    is_valid, result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': result}), 400
    data_dict = result
    
    user_json = data_dict.get('user')
    if not user_json:
        return jsonify({'error': 'Missing user data'}), 400
    try:
        user_data = json.loads(user_json)
        bale_user_id = user_data['id']
    except (json.JSONDecodeError, KeyError):
        return jsonify({'error': 'Invalid user data'}), 400
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='users'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, bale_user_id, username FROM users WHERE bale_user_id = %s", (bale_user_id,))
        user_data_db = cursor.fetchone()
        conn.close()
        
        if user_data_db:
            user = User(user_data_db[0], user_data_db[1], user_data_db[2])
            login_user(user)
            return jsonify({'message': 'Logged in successfully'}), 200
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Auth Test</title>
        <script src="https://tapi.bale.ai/miniapp.js?1"></script>
    </head>
    <body>
        <h1>Auth Test</h1>
        <p id="status">Checking authentication...</p>
        <a href="/logout">Logout</a> | <a href="/protected">Protected Route</a>
        <script>
            window.onload = function() {
                if (typeof Bale !== 'undefined' && Bale.WebApp) {
                    const initData = Bale.WebApp.initData;
                    if (initData) {
                        fetch('/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ initData: initData })
                        })
                        .then(response => {
                            if (response.ok) {
                                return response.json().then(data => {
                                    document.getElementById('status').textContent = data.message;
                                });
                            } else if (response.status === 404) {
                                return fetch('/register', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ initData: initData })
                                }).then(registerResponse => {
                                    if (registerResponse.ok) {
                                        return registerResponse.json().then(data => {
                                            document.getElementById('status').textContent = data.message;
                                        });
                                    }
                                    return registerResponse.json().then(data => {
                                        document.getElementById('status').textContent = 'Error: ' + data.error;
                                    });
                                });
                            }
                            return response.json().then(data => {
                                document.getElementById('status').textContent = 'Error: ' + data.error;
                            });
                        })
                        .catch(error => {
                            document.getElementById('status').textContent = 'Fetch error: ' + error.message;
                        });
                    } else {
                        document.getElementById('status').textContent = 'No initData available';
                    }
                } else {
                    document.getElementById('status').textContent = 'Bale mini-app script not loaded';
                }
            };
        </script>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
