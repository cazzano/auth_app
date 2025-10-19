from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import secrets
import sqlite3
from datetime import datetime, timedelta
import jwt
from functools import wraps
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Change this in production!
JWT_SECRET = secrets.token_hex(32)  # Change this in production!
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_HOURS = 1  # Short-lived access token
JWT_REFRESH_TOKEN_DAYS = 30  # Long-lived refresh token

# Configure OAuth for Google WITH refresh token support
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='511897593718-t4hbe7hqb1slsc9t16hdigljkvqsubag.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent',  # Force consent screen to get refresh token
        'access_type': 'offline'  # REQUEST REFRESH TOKEN!
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
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            given_name TEXT,
            family_name TEXT,
            avatar_url TEXT,
            locale TEXT,
            google_refresh_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            access_token TEXT UNIQUE NOT NULL,
            refresh_token TEXT UNIQUE NOT NULL,
            access_token_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            access_token_expires_at TIMESTAMP NOT NULL,
            refresh_token_expires_at TIMESTAMP NOT NULL,
            is_revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# JWT Token Functions
def generate_access_token(user_id, email):
    current_timestamp = int(time.time())
    payload = {
        'user_id': user_id,
        'email': email,
        'type': 'access',
        'exp': current_timestamp + (JWT_ACCESS_TOKEN_HOURS * 3600),
        'iat': current_timestamp
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_refresh_token(user_id, email):
    current_timestamp = int(time.time())
    payload = {
        'user_id': user_id,
        'email': email,
        'type': 'refresh',
        'exp': current_timestamp + (JWT_REFRESH_TOKEN_DAYS * 86400),
        'iat': current_timestamp
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_token_pair(user_id, email):
    access_token = generate_access_token(user_id, email)
    refresh_token = generate_refresh_token(user_id, email)
    
    # Store both tokens in database
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    access_expires = datetime.utcnow() + timedelta(hours=JWT_ACCESS_TOKEN_HOURS)
    refresh_expires = datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_DAYS)
    
    c.execute('''INSERT INTO tokens 
                 (user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at) 
                 VALUES (?, ?, ?, ?, ?)''',
              (user_id, access_token, refresh_token, access_expires, refresh_expires))
    conn.commit()
    conn.close()
    
    return access_token, refresh_token

def verify_token(token, token_type='access'):
    try:
        # Decode token with leeway
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], 
                           options={"verify_exp": True}, leeway=10)
        
        # Verify token type
        if payload.get('type') != token_type:
            return None
        
        # Check if token is revoked (for access tokens)
        if token_type == 'access':
            conn = sqlite3.connect('ecommerce_users.db')
            c = conn.cursor()
            c.execute('SELECT is_revoked FROM tokens WHERE access_token = ?', (token,))
            result = c.fetchone()
            conn.close()
            
            if not result or result[0] == 1:
                return None
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def revoke_token_pair(access_token):
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    c.execute('UPDATE tokens SET is_revoked = 1 WHERE access_token = ?', (access_token,))
    conn.commit()
    conn.close()

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Access token is missing'}), 401
        
        payload = verify_token(token, 'access')
        if not payload:
            return jsonify({'error': 'Access token is invalid or expired', 
                          'hint': 'Use /api/refresh with your refresh token'}), 401
        
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

def create_or_update_user(google_id, email, name, given_name, family_name, avatar_url, locale, google_refresh_token=None):
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE google_id = ?', (str(google_id),))
    existing_user = c.fetchone()
    
    if existing_user:
        # Only update Google refresh token if we got a new one
        if google_refresh_token:
            c.execute('''
                UPDATE users 
                SET email = ?, name = ?, given_name = ?, family_name = ?, avatar_url = ?, 
                    locale = ?, google_refresh_token = ?, last_login = ?
                WHERE google_id = ?
            ''', (email, name, given_name, family_name, avatar_url, locale, 
                  google_refresh_token, datetime.now(), str(google_id)))
        else:
            c.execute('''
                UPDATE users 
                SET email = ?, name = ?, given_name = ?, family_name = ?, avatar_url = ?, 
                    locale = ?, last_login = ?
                WHERE google_id = ?
            ''', (email, name, given_name, family_name, avatar_url, locale, 
                  datetime.now(), str(google_id)))
        user_id = existing_user[0]
    else:
        c.execute('''
            INSERT INTO users (google_id, email, name, given_name, family_name, avatar_url, 
                             locale, google_refresh_token, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(google_id), email, name, given_name, family_name, avatar_url, locale, 
              google_refresh_token, datetime.now()))
        user_id = c.lastrowid
    
    conn.commit()
    conn.close()
    return user_id

# Routes - OAuth flow endpoints only, no frontend

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
        
        # Get user info
        user_info = token.get('userinfo')
        
        # Get Google's refresh token (only provided on first authorization or when prompt=consent)
        google_refresh_token = token.get('refresh_token')
        
        if user_info:
            user_id = create_or_update_user(
                google_id=user_info['sub'],
                email=user_info['email'],
                name=user_info.get('name'),
                given_name=user_info.get('given_name'),
                family_name=user_info.get('family_name'),
                avatar_url=user_info.get('picture'),
                locale=user_info.get('locale'),
                google_refresh_token=google_refresh_token
            )
            
            # Generate OUR token pair
            access_token, refresh_token = generate_token_pair(user_id, user_info['email'])
            
            session['user'] = {
                'google_id': user_info['sub'],
                'email': user_info['email'],
                'name': user_info.get('name'),
                'given_name': user_info.get('given_name'),
                'family_name': user_info.get('family_name'),
                'avatar_url': user_info.get('picture'),
                'locale': user_info.get('locale'),
                'access_token': access_token,
                'refresh_token': refresh_token,
                'has_google_refresh_token': google_refresh_token is not None
            }
            
            # Return JSON response with tokens instead of redirecting to home
            return jsonify({
                'success': True,
                'message': 'Authentication successful',
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': JWT_ACCESS_TOKEN_HOURS * 3600,
                'user': {
                    'email': user_info['email'],
                    'name': user_info.get('name'),
                    'avatar_url': user_info.get('picture')
                }
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
    return jsonify({'error': 'Authentication failed'}), 400

@app.route('/logout')
def logout():
    user = session.get('user')
    if user and 'access_token' in user:
        revoke_token_pair(user['access_token'])
    session.pop('user', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/profile')
def profile():
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db_user = get_user_by_google_id(user['google_id'])
    
    if db_user:
        return jsonify({
            'success': True,
            'user': {
                'name': db_user['name'],
                'email': db_user['email'],
                'given_name': db_user['given_name'],
                'family_name': db_user['family_name'],
                'avatar_url': db_user['avatar_url'],
                'locale': db_user['locale'],
                'created_at': db_user['created_at'],
                'last_login': db_user['last_login'],
                'has_google_refresh_token': db_user['google_refresh_token'] is not None
            }
        })
    
    return jsonify({'error': 'User not found'}), 404

# API Endpoints
@app.route('/api/user', methods=['GET'])
@token_required
def api_user(user):
    """Get current authenticated user"""
    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'name': user['name'],
            'given_name': user['given_name'],
            'family_name': user['family_name'],
            'avatar_url': user['avatar_url'],
            'locale': user['locale'],
            'created_at': user['created_at'],
            'last_login': user['last_login']
        }
    })

@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Refresh access token using refresh token"""
    data = request.get_json() or {}
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token is required'}), 400
    
    # Verify refresh token
    payload = verify_token(refresh_token, 'refresh')
    if not payload:
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
    
    # Check if token is revoked
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    c.execute('SELECT is_revoked FROM tokens WHERE refresh_token = ?', (refresh_token,))
    result = c.fetchone()
    conn.close()
    
    if not result or result[0] == 1:
        return jsonify({'error': 'Refresh token has been revoked'}), 401
    
    # Generate new access token (keep same refresh token)
    user = get_user_by_id(payload['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    new_access_token = generate_access_token(user['id'], user['email'])
    
    # Update access token in database
    conn = sqlite3.connect('ecommerce_users.db')
    c = conn.cursor()
    new_access_expires = datetime.utcnow() + timedelta(hours=JWT_ACCESS_TOKEN_HOURS)
    c.execute('''UPDATE tokens 
                 SET access_token = ?, access_token_created_at = ?, access_token_expires_at = ?
                 WHERE refresh_token = ?''',
              (new_access_token, datetime.utcnow(), new_access_expires, refresh_token))
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'access_token': new_access_token,
        'token_type': 'Bearer',
        'expires_in': JWT_ACCESS_TOKEN_HOURS * 3600
    })

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout(user):
    """Revoke current token pair"""
    token = request.headers['Authorization'].split(' ')[1]
    revoke_token_pair(token)
    return jsonify({'success': True, 'message': 'Tokens revoked successfully'})

@app.route('/api/health', methods=['GET'])
def api_health():
    """Public endpoint to check API health"""
    return jsonify({'status': 'ok', 'message': 'API is running'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
