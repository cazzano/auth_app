from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import secrets
import sqlite3
from datetime import datetime, timedelta
import jwt
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Change this in production!
JWT_SECRET = secrets.token_hex(32)  # Change this in production!
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Configure OAuth for Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='511897593718-ibeupfvqigdr5ljjoprircckfibcn05j.apps.googleusercontent.com',  # Replace with your Google Client ID
    client_secret='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',  # Replace with your Google Client Secret
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Initialize database
def init_db():
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            name TEXT,
            avatar_url TEXT,
            bio TEXT,
            location TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# JWT Token Functions
def generate_jwt_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Store token in database
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    expires_at = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    c.execute('INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
              (user_id, token, expires_at))
    conn.commit()
    conn.close()
    
    return token

def verify_jwt_token(token):
    try:
        # Check if token is revoked
        conn = sqlite3.connect('ecommerce_users.db')
        c = conn.cursor()
        c.execute('SELECT is_revoked FROM tokens WHERE token = ?', (token,))
        result = c.fetchone()
        conn.close()
        
        if not result or result[0] == 1:
            return None
        
        # Decode token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def revoke_token(token):
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    c.execute('UPDATE tokens SET is_revoked = 1 WHERE token = ?', (token,))
    conn.commit()
    conn.close()

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        # Get user from database
        user = get_user_by_id(payload['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        return f(user, *args, **kwargs)
    
    return decorated

# Database helper functions
def get_user_by_id(user_id):
    conn = sqlite3.connect('ecommerce_users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_google_id(google_id):
    conn = sqlite3.connect('ecommerce_users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE google_id = ?', (str(google_id),))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

def create_or_update_user(google_id, username, email, name, avatar_url, bio=None, location=None):
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE google_id = ?', (str(google_id),))
    existing_user = c.fetchone()
    
    if existing_user:
        c.execute('''
            UPDATE users 
            SET username = ?, email = ?, name = ?, avatar_url = ?, bio = ?, location = ?, last_login = ?
            WHERE google_id = ?
        ''', (username, email, name, avatar_url, bio, location, datetime.now(), str(google_id)))
        user_id = existing_user[0]
    else:
        c.execute('''
            INSERT INTO users (google_id, username, email, name, avatar_url, bio, location, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(google_id), username, email, name, avatar_url, bio, location, datetime.now()))
        user_id = c.lastrowid
    
    conn.commit()
    conn.close()
    return user_id

# Routes
@app.route('/')
def home():
    user = session.get('user')
    if user:
        return f'''
            <h1>Welcome to Our E-commerce Store!</h1>
            <p>Hello, {user['name'] or user['username']}!</p>
            <p>Email: {user['email']}</p>
            <img src="{user['avatar_url']}" alt="Profile Picture" style="border-radius: 50%; width: 100px;">
            <br><br>
            <p><strong>Your API Token:</strong></p>
            <textarea readonly style="width: 600px; height: 100px;">{user['token']}</textarea>
            <p><em>Copy this token to use with API endpoints</em></p>
            <br>
            <a href="/logout"><button>Logout</button></a>
            <a href="/profile"><button>View Profile</button></a>
        '''
    return '''
        <h1>E-commerce Store - Login</h1>
        <p>Please login to continue shopping</p>
        <a href="/login"><button style="background: #4285F4; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
            Login with Google
        </button></a>
    '''

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if user_info:
            # Google provides email as username-like identifier
            # Create username from email (before @)
            email = user_info.get('email')
            username = email.split('@')[0] if email else user_info.get('sub')
            
            user_id = create_or_update_user(
                google_id=user_info['sub'],  # Google's unique user ID
                username=username,
                email=email,
                name=user_info.get('name'),
                avatar_url=user_info.get('picture'),
                bio=None,  # Google doesn't provide bio
                location=None  # Google doesn't provide location
            )
            
            # Generate JWT token
            jwt_token = generate_jwt_token(user_id, username)
            
            session['user'] = {
                'google_id': user_info['sub'],
                'username': username,
                'email': email,
                'name': user_info.get('name'),
                'avatar_url': user_info.get('picture'),
                'bio': None,
                'location': None,
                'token': jwt_token
            }
            
            return redirect('/')
        
    except Exception as e:
        return f'Error: {str(e)}'
    
    return redirect('/')

@app.route('/logout')
def logout():
    user = session.get('user')
    if user and 'token' in user:
        revoke_token(user['token'])
    session.pop('user', None)
    return redirect('/')

@app.route('/profile')
def profile():
    user = session.get('user')
    if not user:
        return redirect('/')
    
    db_user = get_user_by_google_id(user['google_id'])
    
    if db_user:
        return f'''
            <h1>User Profile</h1>
            <img src="{db_user['avatar_url']}" alt="Profile" style="border-radius: 50%; width: 150px;">
            <p><strong>Username:</strong> {db_user['username']}</p>
            <p><strong>Name:</strong> {db_user['name'] or 'Not provided'}</p>
            {f"<p><strong>Email:</strong> {db_user['email']}</p>" if db_user['email'] else ""}
            <p><strong>Account Created:</strong> {db_user['created_at']}</p>
            <p><strong>Last Login:</strong> {db_user['last_login']}</p>
            <br>
            <a href="/"><button>Home</button></a>
            <a href="/logout"><button>Logout</button></a>
        '''
    
    return redirect('/')

# API Endpoints (JWT Protected)
@app.route('/api/user', methods=['GET'])
@token_required
def api_user(user):
    """Get current authenticated user"""
    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'name': user['name'],
            'avatar_url': user['avatar_url'],
            'bio': user['bio'],
            'location': user['location'],
            'created_at': user['created_at'],
            'last_login': user['last_login']
        }
    })

@app.route('/api/profile', methods=['GET'])
@token_required
def api_profile(user):
    """Get user profile"""
    return jsonify({
        'success': True,
        'profile': {
            'username': user['username'],
            'name': user['name'],
            'email': user['email'],
            'avatar_url': user['avatar_url'],
            'bio': user['bio'],
            'location': user['location']
        }
    })

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout(user):
    """Revoke current token"""
    token = request.headers['Authorization'].split(' ')[1]
    revoke_token(token)
    return jsonify({'success': True, 'message': 'Token revoked successfully'})

@app.route('/api/health', methods=['GET'])
def api_health():
    """Public endpoint to check API health"""
    return jsonify({'status': 'ok', 'message': 'API is running'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
