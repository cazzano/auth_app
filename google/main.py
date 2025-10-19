from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import secrets
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, UTC
import jwt
from functools import wraps
import time
import atexit
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_HOURS = 1
JWT_REFRESH_TOKEN_DAYS = 30

# PostgreSQL Connection Configuration
DATABASE_URL = "postgresql://whale:iC9_vZ0_jZ2-jN3_pX2+@asia-south2-001.proxy.kinsta.app:30219/semantic-amaranth-leopon"

# Pool state
db_pool = None
pool_closed = False

def init_pool():
    global db_pool
    if db_pool is None:
        db_pool = pool.SimpleConnectionPool(1, 20, DATABASE_URL)
        print("Connection pool initialized")

def get_db_connection():
    global db_pool
    if db_pool is None:
        init_pool()
    return db_pool.getconn()

def close_db_connection(conn):
    global db_pool, pool_closed
    if conn and db_pool and not pool_closed:
        try:
            db_pool.putconn(conn)
        except Exception as e:
            print(f"Error returning connection to pool: {e}")

# Configure OAuth for Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='511897593718-t4hbe7hqb1slsc9t16hdigljkvqsubag.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent',
        'access_type': 'offline'
    }
)

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
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
                id SERIAL PRIMARY KEY,
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
        
        c.execute('CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token)')
        
        conn.commit()
        print("Database initialized successfully!")
    except Exception as e:
        print(f"Database initialization error: {e}")
        conn.rollback()
    finally:
        c.close()
        close_db_connection(conn)

init_pool()
init_db()

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
    
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        access_expires = datetime.now(UTC) + timedelta(hours=JWT_ACCESS_TOKEN_HOURS)
        refresh_expires = datetime.now(UTC) + timedelta(days=JWT_REFRESH_TOKEN_DAYS)
        
        c.execute('''INSERT INTO tokens 
                     (user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at) 
                     VALUES (%s, %s, %s, %s, %s)''',
                  (user_id, access_token, refresh_token, access_expires, refresh_expires))
        conn.commit()
    except Exception as e:
        print(f"Error generating token pair: {e}")
        conn.rollback()
    finally:
        c.close()
        close_db_connection(conn)
    
    return access_token, refresh_token

def verify_token(token, token_type='access'):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], 
                           options={"verify_exp": True}, leeway=10)
        
        if payload.get('type') != token_type:
            return None
        
        if token_type == 'access':
            conn = get_db_connection()
            c = conn.cursor()
            
            try:
                c.execute('SELECT is_revoked FROM tokens WHERE access_token = %s', (token,))
                result = c.fetchone()
                
                if not result or result[0] == 1:
                    return None
            finally:
                c.close()
                close_db_connection(conn)
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def revoke_token_pair(access_token):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute('UPDATE tokens SET is_revoked = 1 WHERE access_token = %s', (access_token,))
        conn.commit()
    except Exception as e:
        print(f"Error revoking token: {e}")
        conn.rollback()
    finally:
        c.close()
        close_db_connection(conn)

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

def get_user_by_id(user_id):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        c.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = c.fetchone()
        return dict(user) if user else None
    finally:
        c.close()
        close_db_connection(conn)

def get_user_by_google_id(google_id):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        c.execute('SELECT * FROM users WHERE google_id = %s', (str(google_id),))
        user = c.fetchone()
        return dict(user) if user else None
    finally:
        c.close()
        close_db_connection(conn)

def create_or_update_user(google_id, email, name, given_name, family_name, avatar_url, locale, google_refresh_token=None):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute('SELECT id FROM users WHERE google_id = %s', (str(google_id),))
        existing_user = c.fetchone()
        
        if existing_user:
            if google_refresh_token:
                c.execute('''
                    UPDATE users 
                    SET email = %s, name = %s, given_name = %s, family_name = %s, avatar_url = %s, 
                        locale = %s, google_refresh_token = %s, last_login = %s
                    WHERE google_id = %s
                ''', (email, name, given_name, family_name, avatar_url, locale, 
                      google_refresh_token, datetime.now(UTC), str(google_id)))
            else:
                c.execute('''
                    UPDATE users 
                    SET email = %s, name = %s, given_name = %s, family_name = %s, avatar_url = %s, 
                        locale = %s, last_login = %s
                    WHERE google_id = %s
                ''', (email, name, given_name, family_name, avatar_url, locale, 
                      datetime.now(UTC), str(google_id)))
            user_id = existing_user[0]
        else:
            c.execute('''
                INSERT INTO users (google_id, email, name, given_name, family_name, avatar_url, 
                                 locale, google_refresh_token, last_login)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (str(google_id), email, name, given_name, family_name, avatar_url, locale, 
                  google_refresh_token, datetime.now(UTC)))
            user_id = c.fetchone()[0]
        
        conn.commit()
        return user_id
    except Exception as e:
        print(f"Error creating/updating user: {e}")
        conn.rollback()
        raise
    finally:
        c.close()
        close_db_connection(conn)

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
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

@app.route('/api/user', methods=['GET'])
@token_required
def api_user(user):
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
    data = request.get_json() or {}
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token is required'}), 400
    
    payload = verify_token(refresh_token, 'refresh')
    if not payload:
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
    
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute('SELECT is_revoked FROM tokens WHERE refresh_token = %s', (refresh_token,))
        result = c.fetchone()
        
        if not result or result[0] == 1:
            return jsonify({'error': 'Refresh token has been revoked'}), 401
    finally:
        c.close()
        close_db_connection(conn)
    
    user = get_user_by_id(payload['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    new_access_token = generate_access_token(user['id'], user['email'])
    
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        new_access_expires = datetime.now(UTC) + timedelta(hours=JWT_ACCESS_TOKEN_HOURS)
        c.execute('''UPDATE tokens 
                     SET access_token = %s, access_token_created_at = %s, access_token_expires_at = %s
                     WHERE refresh_token = %s''',
                  (new_access_token, datetime.now(UTC), new_access_expires, refresh_token))
        conn.commit()
    except Exception as e:
        print(f"Error updating token: {e}")
        conn.rollback()
    finally:
        c.close()
        close_db_connection(conn)
    
    return jsonify({
        'success': True,
        'access_token': new_access_token,
        'token_type': 'Bearer',
        'expires_in': JWT_ACCESS_TOKEN_HOURS * 3600
    })

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout(user):
    token = request.headers['Authorization'].split(' ')[1]
    revoke_token_pair(token)
    return jsonify({'success': True, 'message': 'Tokens revoked successfully'})

@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'status': 'ok', 'message': 'API is running'})

def close_pool_on_exit():
    global db_pool, pool_closed
    if db_pool and not pool_closed:
        try:
            db_pool.closeall()
            pool_closed = True
            print("Connection pool closed")
        except Exception as ex:
            print(f"Error closing pool: {ex}")

atexit.register(close_pool_on_exit)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
