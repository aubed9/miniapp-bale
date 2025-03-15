from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
import hmac
import hashlib
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
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
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
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
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

# Bot token
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"

# Custom URL decoding functions
def url_decode(s):
    bytes_list = []
    i = 0
    while i < len(s):
        if s[i] == '%':
            try:
                hex_code = s[i+1:i+3]
                byte_val = int(hex_code, 16)
                bytes_list.append(byte_val)
                i += 3
            except (ValueError, IndexError):
                bytes_list.append(ord('%'))
                i += 1
        elif s[i] == '+':
            bytes_list.append(0x20)
            i += 1
        else:
            bytes_list.append(ord(s[i]))
            i += 1
    return bytes(bytes_list).decode('utf-8', errors='replace')

def parse_qs(query_string):
    params = {}
    pairs = query_string.split('&')
    for pair in pairs:
        if not pair:
            continue
        parts = pair.split('=', 1)
        key = url_decode(parts[0])
        value = url_decode(parts[1]) if len(parts) > 1 else ''
        if key in params:
            if isinstance(params[key], list):
                params[key].append(value)
            else:
                params[key] = [params[key], value]
        else:
            params[key] = value
    return params

# Validate initData
def validate_init_data(init_data):
    decoded_init_data = url_decode(init_data)
    parsed_data = parse_qs(decoded_init_data)
    data_dict = {k: v[0] if isinstance(v, list) else v for k, v in parsed_data.items()}
    hash_value = data_dict.pop('hash', None)
    if not hash_value:
        return False, "Missing hash in initData"
    sorted_keys = sorted(data_dict.keys())
    data_check_string = "\n".join([f"{k}={data_dict[k]}" for k in sorted_keys])
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    check_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if check_hash != hash_value:
        return False, "Invalid hash, data may be tampered"
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
            host='annapurna.liara.cloud',
            user='root',
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
            port=32002,
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE bale_user_id = %s", (bale_user_id,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
        cursor.execute("INSERT INTO users (bale_user_id, username) VALUES (%s, %s)", 
                       (bale_user_id, username))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        user = User(user_id, bale_user_id, username)
        login_user(user)
        return jsonify({'message': 'User registered and logged in successfully'}), 201
    except Exception as e:
        print(f"Error in register: {e}")
        return jsonify({'error': 'Database error'}), 500

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
            host='annapurna.liara.cloud',
            user='root',
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
            port=32002,
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, bale_user_id, username FROM users WHERE bale_user_id = %s", (bale_user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user)
            return jsonify({'message': 'Logged in successfully'}), 200
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
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
                                window.location.href = '/dashboard';
                            } else if (response.status === 404) {
                                return fetch('/register', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ initData: initData })
                                }).then(registerResponse => {
                                    if (registerResponse.ok) {
                                        window.location.href = '/dashboard';
                                    } else {
                                        return registerResponse.json().then(data => {
                                            document.getElementById('status').textContent = 'Registration error: ' + data.error;
                                        });
                                    }
                                });
                            } else {
                                return response.json().then(data => {
                                    document.getElementById('status').textContent = 'Login error: ' + data.error;
                                });
                            }
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

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard</title>
    </head>
    <body>
        <h1>Welcome to the Dashboard, {{ current_user.username }}!</h1>
        <a href="/logout">Logout</a>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
