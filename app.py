from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import psycopg2
from psycopg2 import pool
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta
import json
from pyngrok import ngrok
import threading
import requests
from dotenv import load_dotenv
import os

# Initialize PostgreSQL connection pool
postgresql_pool = None

def start_ngrok():
    ngrok.set_auth_token("2zQnShLrqinHKmckJnYqI5XEtMZ_4nRHF9nSXK1BLvfHxfC5F")
    public_url = ngrok.connect(5000).public_url
    print(f"\nPaystack Webhook URL: {public_url}/paystack-webhook")
    print("Note: This URL changes each time you restart ngrok\n")

if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or os.environ.get('FLASK_ENV') != 'production':
    threading.Thread(target=start_ngrok).start()

def expose_localhost():
    try:
        res = requests.post("https://api.expose.sh/tunnels", json={
            "subdomain": "yourproject",
            "port": 5000
        }).json()
        print(f"\nPaystack Webhook URL: {res['url']}/paystack-webhook")
    except Exception as e:
        print(f"Couldn't get public URL. Manually use ngrok instead.\nError: {e}")

# Load environment variables
load_dotenv()

# Initialize database pool
def init_db_pool():
    global postgresql_pool
    postgresql_pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        host=os.getenv('POSTGRES_HOST', ),
        database=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER', ),
        password=os.getenv('POSTGRES_PASSWORD'),
        port=os.getenv('POSTGRES_PORT')
    )
    

def get_db_connection():
    return postgresql_pool.getconn()

def release_db_connection(conn):
    postgresql_pool.putconn(conn)

# ClubConnect API Configuration
CLUBCONNECT_API_KEYS = {
    'AIRTIME': os.getenv('CLUBCONNECT_AIRTIME_API_KEY'),
    'DATA': os.getenv('CLUBCONNECT_DATA_API_KEY'),
    'TV': os.getenv('CLUBCONNECT_TV_API_KEY'),
    'ELECTRICITY': os.getenv('CLUBCONNECT_ELECTRICITY_API_KEY'),
    'EDUCATION': os.getenv('CLUBCONNECT_EDUCATION_API_KEY')
}

CLUBCONNECT_BASE_URL = os.getenv('CLUBCONNECT_BASE_URL')

# Paystack Configuration
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY')
PAYSTACK_BASE_URL = "https://api.paystack.co"

# Validate all API keys
for service, key in CLUBCONNECT_API_KEYS.items():
    if not key:
        raise ValueError(f"Missing API key for {service} service in .env file!")

# API Endpoints
CLUBCONNECT_ENDPOINTS = {
    'BALANCE': '/account/balance',
    'AIRTIME': '/vtu/airtime',
    'DATA': '/vtu/data',
    'TV': '/vtu/tv',
    'ELECTRICITY': '/vtu/electricity',
    'WAEC': '/education/waec',                              
    'JAMB': '/education/jamb'
}

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')

# Database Initialization
def init_notifications_db():
    """Initializes the notifications table if it doesn't exist."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_email TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()
    finally:
        release_db_connection(conn)

def init_users_db():
    """Initializes the users table if it doesn't exist."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                fullname TEXT NOT NULL,
                phone TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                pin_hash TEXT,
                balance NUMERIC(12, 2) DEFAULT 0.00,
                transactions TEXT,
                initial_notifications_sent BOOLEAN DEFAULT FALSE,
                virtual_account JSONB
            )
            ''')
            conn.commit()
    finally:
        release_db_connection(conn)

# Initialize databases
init_db_pool()
init_notifications_db()
init_users_db()

# Helper Functions
def add_user_to_db(email, fullname, phone, password_hash, pin_hash, balance=0.00):
    """Adds a new user to the database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''INSERT INTO users 
                (email, fullname, phone, password_hash, pin_hash, balance, transactions, initial_notifications_sent) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (email, fullname, phone, password_hash, pin_hash, balance, '[]', False)
            )
            conn.commit()
            return True
    except psycopg2.IntegrityError:
        return False
    finally:
        release_db_connection(conn)

def get_user_from_db(email):
    """Retrieves user data from the database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user_row = cursor.fetchone()
            if user_row:
                return {
                    "email": user_row[0],
                    "fullname": user_row[1],
                    "phone": user_row[2],
                    "password": user_row[3],
                    "pin_hash": user_row[4],
                    "balance": float(user_row[5]) if user_row[5] else 0.00,
                    "transactions": json.loads(user_row[6]) if user_row[6] else [],
                    "initial_notifications_sent": user_row[7],
                    "virtual_account": user_row[8] if user_row[8] else None
                }
        return None
    finally:
        release_db_connection(conn)

def update_user_in_db(user_data):
    """Updates user data in the database."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''UPDATE users SET 
                fullname=%s, phone=%s, password_hash=%s, pin_hash=%s, 
                balance=%s, transactions=%s, initial_notifications_sent=%s, virtual_account=%s
                WHERE email=%s''',
                (user_data['fullname'], user_data['phone'], user_data['password'],
                 user_data['pin_hash'], user_data['balance'],
                 json.dumps(user_data['transactions']), 
                 user_data['initial_notifications_sent'],
                 json.dumps(user_data.get('virtual_account')) if user_data.get('virtual_account') else None,
                 user_data['email'])
            )
            conn.commit()
    finally:
        release_db_connection(conn)

def add_notification(email, message):
    """Adds a notification for the user."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'INSERT INTO notifications (user_email, message) VALUES (%s, %s)',
                (email, message)
            )
            conn.commit()
    finally:
        release_db_connection(conn)

def get_user_notifications(email):
    """Gets all notifications for a user."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT message, TO_CHAR(created_at, 'HH24:MI') as time, is_read
                FROM notifications
                WHERE user_email = %s
                ORDER BY created_at DESC
                LIMIT 50
            ''', (email,))
            return cursor.fetchall()
    finally:
        release_db_connection(conn)

def clear_notifications(email):
    """Clears all notifications for a user."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'DELETE FROM notifications WHERE user_email = %s',
                (email,)
            )
            conn.commit()
    finally:
        release_db_connection(conn)

def generate_token(email):
    """Generates a password reset token."""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def verify_token(token, expiration=3600):
    """Verifies a password reset token."""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
        return email
    except:
        return False

# ClubConnect API Functions
def call_clubconnect_api(service_type, endpoint, data):
    """Make authenticated requests to ClubConnect API with service-specific keys"""
    headers = {
        'Authorization': f'Bearer {CLUBCONNECT_API_KEYS[service_type]}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f'{CLUBCONNECT_BASE_URL}{endpoint}',
            headers=headers,
            json=data,
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"API Error ({service_type} - {endpoint}): {str(e)}")
        return {
            "status": "error",
            "message": "Service temporarily unavailable",
            "details": str(e)
        }

def check_clubconnect_balance(service_type):
    """Check ClubConnect wallet balance for specific service"""
    response = call_clubconnect_api(service_type, CLUBCONNECT_ENDPOINTS['BALANCE'], {})
    if response.get('status') == 'success':
        return float(response.get('balance', 0))
    return 0

# ==============================================================================
# Application Routes
# ==============================================================================

@app.route("/")
def home():
    return render_template("index.html",
                         app_name="LIGHTPLUG",
                         tagline="Power Up Instantly ⚡")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email').lower()
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        pin = request.form.get('pin')

        # Validation
        if not all([fullname, email, phone, password, confirm_password, pin]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        if len(pin) != 4 or not pin.isdigit():
            flash('PIN must be 4 digits', 'error')
            return redirect(url_for('register'))

        if get_user_from_db(email):
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))

        # Create user
        password_hash = generate_password_hash(password)
        pin_hash = generate_password_hash(pin)

        if add_user_to_db(email, fullname, phone, password_hash, pin_hash):
            session['user_email'] = email
            session['user_fullname'] = fullname
            flash('Registration successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Registration failed, please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if not all([email, password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('login'))

        user = get_user_from_db(email)
        if not user or not check_password_hash(user['password'], password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        session['user_email'] = email
        session['user_fullname'] = user['fullname']
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        if not email:
            flash('Email is required', 'error')
            return redirect(url_for('forgot_password'))

        if not get_user_from_db(email):
            flash('If this email exists, a reset link has been sent', 'info')
            return redirect(url_for('login'))

        token = generate_token(email)
        reset_url = url_for('reset_password', token=token, _external=True)
        print(f"Password reset link: {reset_url}")  # In production, send email
        flash('Password reset link sent to your email', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if not email:
        flash('Invalid or expired token', 'error')
        return redirect(url_for('forgot_password'))

    user = get_user_from_db(email)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('reset_password', token=token))

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password', token=token))

        user['password'] = generate_password_hash(new_password)
        update_user_in_db(user)
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    if not user['initial_notifications_sent']:
        add_notification(user['email'], "Welcome to LIGHTPLUG!")
        add_notification(user['email'], "Complete your profile setup")
        user['initial_notifications_sent'] = True
        update_user_in_db(user)

    if not user['transactions']:
        user['transactions'].extend([
            {
                "service": "Initial Deposit",
                "amount": 5000.00,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "success",
                "transaction_id": "SAMPLE_DEP_1"
            },
            {
                "service": "Airtime Purchase",
                "amount": -500.00,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "success",
                "transaction_id": "SAMPLE_AIR_1"
            }
        ])
        update_user_in_db(user)

    return render_template('dashboard.html',
                         user=user,
                         balance=user['balance'],
                         transactions=user['transactions'])

@app.route('/notifications')
def view_notifications():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    notifications = get_user_notifications(session['user_email'])
    return jsonify({
        'count': sum(1 for n in notifications if not n[2]),
        'notifications': [
            {'message': n[0], 'time': n[1], 'read': bool(n[2])}
            for n in notifications
        ]
    })

@app.route('/notifications/clear', methods=['POST'])
def clear_notifs():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    clear_notifications(session['user_email'])
    return jsonify({'success': True})

@app.route('/profile')
def profile():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    return render_template('profile.html', user=user)

@app.route('/profile/update', methods=['POST'])
def update_profile():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    user['fullname'] = request.form.get('fullname')
    user['phone'] = request.form.get('phone')
    update_user_in_db(user)
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/setup-pin', methods=['GET', 'POST'])
def setup_pin():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        pin = request.form.get('pin')
        confirm_pin = request.form.get('confirm_pin')

        if len(pin) != 4 or not pin.isdigit():
            flash('PIN must be 4 digits', 'error')
            return redirect(url_for('setup_pin'))

        if pin != confirm_pin:
            flash('PINs do not match', 'error')
            return redirect(url_for('setup_pin'))

        user['pin_hash'] = generate_password_hash(pin)
        update_user_in_db(user)
        flash('PIN set successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('setup_pin.html', user=user)

@app.route('/verify-pin', methods=['POST'])
def verify_pin():
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})

    user = get_user_from_db(session['user_email'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})

    entered_pin = request.get_json().get('pin')
    if not entered_pin or len(entered_pin) != 4:
        return jsonify({'success': False, 'message': 'Invalid PIN format'})

    if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
        return jsonify({'success': False, 'message': 'Incorrect PIN'})

    return jsonify({'success': True})

@app.route("/success")
def transaction_success():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    transaction_id = request.args.get("transaction_id")
    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('dashboard'))

    transaction = next((t for t in user['transactions']
                      if t.get('transaction_id') == transaction_id), None)

    if not transaction:
        flash('Transaction not found', 'error')
        return redirect(url_for('dashboard'))

    return render_template("success.html",
                         transaction=transaction,
                         user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

# ==============================================================================
# VTU Service Routes (Complete Implementations)
# ==============================================================================

@app.route('/buy-airtime', methods=['GET', 'POST'])
def buy_airtime():
    if 'user_email' not in session:
        flash('Please login to continue', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        phone = request.form.get('phone', user['phone'])
        amount = float(request.form.get('amount'))
        network = request.form.get('network')

        if not all([phone, amount, network]):
            return jsonify({'success': False, 'message': 'All fields are required'})

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        if user['balance'] < amount:
            return jsonify({'success': False, 'message': 'Insufficient user balance'})

        clubconnect_balance = check_clubconnect_balance('AIRTIME')
        if clubconnect_balance < amount:
            return jsonify({'success': False, 'message': 'Airtime service temporarily unavailable'})

        api_response = call_clubconnect_api('AIRTIME', CLUBCONNECT_ENDPOINTS['AIRTIME'], {
            'phone': phone,
            'amount': amount,
            'network': network
        })

        if api_response.get('status') == 'success':
            user['balance'] -= amount
            transaction = {
                'transaction_id': api_response.get('transaction_id'),
                'service': f'{network} Airtime',
                'amount': -amount,
                'phone': phone,
                'status': 'success',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            user['transactions'].append(transaction)
            update_user_in_db(user)
            
            return jsonify({
                'success': True,
                'message': 'Airtime purchase successful!',
                'transaction_id': transaction['transaction_id']
            })
        else:
            return jsonify({
                'success': False,
                'message': api_response.get('message', 'Airtime purchase failed')
            })

    return render_template('airtime.html', user=user)

@app.route('/buy-data', methods=['GET', 'POST'])
def buy_data():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    data_plans = {
        "MTN": [
            {"id": "MTN-100MB", "name": "100MB", "price": 100, "validity": "1 day"},
            {"id": "MTN-1GB", "name": "1GB", "price": 500, "validity": "30 days"}
        ],
        "Airtel": [
            {"id": "AIRTEL-100MB", "name": "100MB", "price": 100, "validity": "1 day"},
            {"id": "AIRTEL-1GB", "name": "1GB", "price": 500, "validity": "30 days"}
        ]
    }

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        phone = request.form.get('phone', user['phone'])
        network = request.form.get('network')
        plan_id = request.form.get('plan_id')
        
        selected_plan = next(
            (p for provider in data_plans.values() for p in provider if p['id'] == plan_id),
            None
        )
        
        if not selected_plan:
            return jsonify({'success': False, 'message': 'Invalid data plan selected'})

        if user['balance'] < selected_plan['price']:
            return jsonify({'success': False, 'message': 'Insufficient user balance'})

        clubconnect_balance = check_clubconnect_balance('DATA')
        if clubconnect_balance < selected_plan['price']:
            return jsonify({'success': False, 'message': 'Data service temporarily unavailable'})

        api_response = call_clubconnect_api('DATA', CLUBCONNECT_ENDPOINTS['DATA'], {
            'phone': phone,
            'plan_id': plan_id,
            'network': network
        })

        if api_response.get('status') == 'success':
            user['balance'] -= selected_plan['price']
            transaction = {
                'transaction_id': api_response.get('transaction_id'),
                'service': f'{network} {selected_plan["name"]} Data',
                'amount': -selected_plan['price'],
                'phone': phone,
                'status': 'success',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            user['transactions'].append(transaction)
            update_user_in_db(user)
            
            return jsonify({
                'success': True,
                'message': 'Data purchase successful!',
                'transaction_id': transaction['transaction_id']
            })
        else:
            return jsonify({
                'success': False,
                'message': api_response.get('message', 'Data purchase failed')
            })

    return render_template('buy_data.html', user=user, data_plans=data_plans, balance=user['balance'])

@app.route('/tv-payment', methods=['GET', 'POST'])
def tv_payment():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    tv_packages = {
        "DSTV": [
            {"code": "DSTV-Padi", "name": "DStv Padi", "price": 2100},
            {"code": "DSTV-Compact", "name": "DStv Compact", "price": 6100}
        ],
        "GOTV": [
            {"code": "GOTV-Jinja", "name": "GOtv Jinja", "price": 1900},
            {"code": "GOTV-Maxi", "name": "GOtv Maxi", "price": 3600}
        ]
    }

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        decoder_number = request.form.get('decoder_number')
        provider = request.form.get('provider')
        package_code = request.form.get('package_code')
        
        selected_package = next(
            (p for provider_pkgs in tv_packages.values() for p in provider_pkgs if p['code'] == package_code),
            None
        )
        
        if not selected_package:
            return jsonify({'success': False, 'message': 'Invalid TV package selected'})

        if user['balance'] < selected_package['price']:
            return jsonify({'success': False, 'message': 'Insufficient user balance'})

        clubconnect_balance = check_clubconnect_balance('TV')
        if clubconnect_balance < selected_package['price']:
            return jsonify({'success': False, 'message': 'TV service temporarily unavailable'})

        api_response = call_clubconnect_api('TV', CLUBCONNECT_ENDPOINTS['TV'], {
            'decoder_number': decoder_number,
            'provider': provider,
            'package_code': package_code,
            'amount': selected_package['price']
        })

        if api_response.get('status') == 'success':
            user['balance'] -= selected_package['price']
            transaction = {
                'transaction_id': api_response.get('transaction_id'),
                'service': f'{provider} {selected_package["name"]}',
                'amount': -selected_package['price'],
                'decoder_number': decoder_number,
                'status': 'success',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            user['transactions'].append(transaction)
            update_user_in_db(user)
            
            return jsonify({
                'success': True,
                'message': 'TV payment successful!',
                'transaction_id': transaction['transaction_id']
            })
        else:
            return jsonify({
                'success': False,
                'message': api_response.get('message', 'TV payment failed')
            })

    return render_template('tv_payment.html', user=user, tv_packages=tv_packages,balance=user['balance'])

@app.route('/electricity-bills', methods=['GET', 'POST'])
def electricity_bills():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    discos = ["IKEDC", "EKEDC", "PHED", "KEDCO"]  # Sample distribution companies

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        meter_number = request.form.get('meter_number')
        disco = request.form.get('disco')
        meter_type = request.form.get('meter_type', 'prepaid')
        amount = float(request.form.get('amount'))

        if not all([meter_number, disco, amount]):
            return jsonify({'success': False, 'message': 'All fields are required'})

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        if user['balance'] < amount:
            return jsonify({'success': False, 'message': 'Insufficient user balance'})

        clubconnect_balance = check_clubconnect_balance('ELECTRICITY')
        if clubconnect_balance < amount:
            return jsonify({'success': False, 'message': 'Electricity service temporarily unavailable'})

        api_response = call_clubconnect_api('ELECTRICITY', CLUBCONNECT_ENDPOINTS['ELECTRICITY'], {
            'meter_number': meter_number,
            'disco': disco,
            'meter_type': meter_type,
            'amount': amount
        })

        if api_response.get('status') == 'success':
            user['balance'] -= amount
            transaction = {
                'transaction_id': api_response.get('transaction_id'),
                'service': f'{disco} Electricity',
                'amount': -amount,
                'meter_number': meter_number,
                'status': 'success',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            user['transactions'].append(transaction)
            update_user_in_db(user)
            
            return jsonify({
                'success': True,
                'message': 'Electricity payment successful!',
                'transaction_id': transaction['transaction_id']
            })
        else:
            return jsonify({
                'success': False,
                'message': api_response.get('message', 'Electricity payment failed')
            })

    return render_template('electricity_bills.html', user=user, discos=discos, balance=user['balance'])

@app.route('/education-pin', methods=['GET', 'POST'])
def education_pins():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    exam_types = {
        "WAEC": {"price": 1500, "name": "WAEC Scratch Card"},
        "JAMB": {"price": 5000, "name": "JAMB e-PIN"}
    }

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        exam_type = request.form.get('exam_type')
        quantity = int(request.form.get('quantity', 1))
        
        if exam_type not in exam_types:
            return jsonify({'success': False, 'message': 'Invalid exam type selected'})

        total_amount = exam_types[exam_type]['price'] * quantity

        if user['balance'] < total_amount:
            return jsonify({'success': False, 'message': 'Insufficient user balance'})

        clubconnect_balance = check_clubconnect_balance('EDUCATION')
        if clubconnect_balance < total_amount:
            return jsonify({'success': False, 'message': 'Education service temporarily unavailable'})

        api_response = call_clubconnect_api('EDUCATION', CLUBCONNECT_ENDPOINTS[exam_type], {
            'quantity': quantity
        })

        if api_response.get('status') == 'success':
            user['balance'] -= total_amount
            transaction = {
                'transaction_id': api_response.get('transaction_id'),
                'service': f'{exam_types[exam_type]["name"]} ({quantity}x)',
                'amount': -total_amount,
                'quantity': quantity,
                'status': 'success',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            user['transactions'].append(transaction)
            update_user_in_db(user)
            
            return jsonify({
                'success': True,
                'message': 'Education PIN purchase successful!',
                'transaction_id': transaction['transaction_id'],
                'pins': api_response.get('pins', [])  # Actual PINs from API
            })
        else:
            return jsonify({
                'success': False,
                'message': api_response.get('message', 'Education PIN purchase failed')
            })

    return render_template('education_pins.html', user=user, exam_types=exam_types, balance=user['balance'])

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        amount = float(request.form.get('amount'))
        payment_method = 'bank_transfer'  # Default for virtual account deposits

        if not amount or amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        # For virtual account deposits, we don't need to process immediately
        # Paystack will notify via webhook when payment is received
        transaction = {
            "transaction_id": f"DP{int(datetime.now().timestamp())}",
            "service": "Deposit via Virtual Account",
            "amount": amount,
            "payment_method": payment_method,
            "status": "pending",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if not user.get('transactions'):
            user['transactions'] = []
        user['transactions'].append(transaction)
        update_user_in_db(user)

        return jsonify({
            'success': True,
            'message': 'Deposit initiated. Transfer to your virtual account.',
            'redirect_url': url_for('dashboard')
        })

    return render_template('deposit.html', user=user)

@app.route('/verify-paystack-payment/<reference>')
def verify_paystack_payment(reference):
    if 'user_email' not in session:
        return jsonify({'status': False, 'message': 'Not logged in'})

    # Verify payment with Paystack
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(
            f'{PAYSTACK_BASE_URL}/transaction/verify/{reference}',
            headers=headers
        )
        data = response.json()

        if data['status'] and data['data']['status'] == 'success':
            amount = data['data']['amount'] / 100  # Convert to Naira
            user = get_user_from_db(session['user_email'])
            
            # Update balance
            user['balance'] += amount
            transaction = {
                "transaction_id": reference,
                "service": "Paystack Deposit",
                "amount": amount,
                "payment_method": "Card",
                "status": "success",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            user['transactions'].append(transaction)
            update_user_in_db(user)

            return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Paystack verification error: {str(e)}")
    
    flash('Payment verification failed', 'error')
    return redirect(url_for('deposit'))

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        amount = float(request.form.get('amount'))
        bank_name = request.form.get('bank_name')
        account_number = request.form.get('account_number')

        if not all([amount, bank_name, account_number]):
            return jsonify({'success': False, 'message': 'All fields are required'})

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        if user['balance'] < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'})

        user['balance'] -= amount
        transaction = {
            "transaction_id": f"WD{int(datetime.now().timestamp())}",
            "service": "Withdrawal",
            "amount": -amount,
            "bank_name": bank_name,
            "account_number": account_number,
            "status": "pending",  # Marked as pending until bank confirms
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        user['transactions'].append(transaction)
        update_user_in_db(user)

        flash(f'Withdrawal request of ₦{amount:.2f} submitted!', 'success')
        return jsonify({
            'success': True,
            'redirect_url': url_for('dashboard')
        })

    return render_template('withdraw.html', user=user)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = get_user_from_db(session['user_email'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_pin = request.form.get('transaction_pin')
        if not user.get('pin_hash') or not check_password_hash(user['pin_hash'], entered_pin):
            return jsonify({'success': False, 'message': 'Incorrect transaction PIN'})

        recipient_email = request.form.get('recipient_email').lower()
        amount = float(request.form.get('amount'))

        if not all([recipient_email, amount]):
            return jsonify({'success': False, 'message': 'All fields are required'})

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        if user['balance'] < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'})

        recipient = get_user_from_db(recipient_email)
        if not recipient:
            return jsonify({'success': False, 'message': 'Recipient not found'})

        # Process transfer
        user['balance'] -= amount
        recipient['balance'] += amount

        transaction_id = f"TF{int(datetime.now().timestamp())}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sender's transaction
        user['transactions'].append({
            "transaction_id": transaction_id,
            "service": f"Transfer to {recipient_email}",
            "amount": -amount,
            "status": "success",
            "timestamp": timestamp
        })

        # Recipient's transaction
        recipient['transactions'].append({
            "transaction_id": transaction_id,
            "service": f"Transfer from {user['email']}",
            "amount": amount,
            "status": "success",
            "timestamp": timestamp
        })

        update_user_in_db(user)
        update_user_in_db(recipient)

        flash(f'Transfer of ₦{amount:.2f} to {recipient_email} successful!', 'success')
        return jsonify({
            'success': True,
            'redirect_url': url_for('dashboard')
        })

    return render_template('transfer.html', user=user)

@app.route('/generate-virtual-account', methods=['POST'])
def generate_virtual_account():
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})

    user = get_user_from_db(session['user_email'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})

    # Check if user already has an account in database
    if user.get('virtual_account'):
        return jsonify({
            'success': True,
            'account_number': user['virtual_account']['account_number'],
            'account_name': user['virtual_account']['account_name'],
            'bank': user['virtual_account']['bank']
        })

    # Create via Paystack API
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'customer': {
            'email': user['email'],
            'first_name': user['fullname'].split()[0],
            'last_name': ' '.join(user['fullname'].split()[1:]) if len(user['fullname'].split()) > 1 else '',
            'phone': user['phone']
        },
        'preferred_bank': 'wema-bank',  # Can be dynamic if needed
        'country': 'NG'
    }

    try:
        response = requests.post(
            f'{PAYSTACK_BASE_URL}/dedicated_account',
            headers=headers,
            json=payload
        )
        data = response.json()

        if data.get('status'):
            # Save to user profile
            user['virtual_account'] = {
                'account_number': data['data']['account_number'],
                'account_name': data['data']['account_name'],
                'bank': data['data']['bank']['name'],
                'provider': 'paystack'
            }
            update_user_in_db(user)

            return jsonify({
                'success': True,
                'account_number': data['data']['account_number'],
                'account_name': data['data']['account_name'],
                'bank': data['data']['bank']['name']
            })
    except Exception as e:
        print(f"Paystack error: {str(e)}")

    return jsonify({'success': False, 'message': 'Failed to generate account. Please try again.'})

@app.route('/validate-bank-account', methods=['POST'])
def validate_bank_account():
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})

    data = request.get_json()
    bank_code = get_bank_code(data['bank_name'])  # Implement this helper
    account_number = data['account_number']

    # Verify account with Paystack
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    try:
        # Resolve account number
        resolve_response = requests.get(
            f'{PAYSTACK_BASE_URL}/bank/resolve?account_number={account_number}&bank_code={bank_code}',
            headers=headers
        )
        resolve_data = resolve_response.json()

        if resolve_data['status']:
            # Create transfer recipient
            recipient_response = requests.post(
                f'{PAYSTACK_BASE_URL}/transferrecipient',
                headers=headers,
                json={
                    'type': 'nuban',
                    'name': resolve_data['data']['account_name'],
                    'account_number': account_number,
                    'bank_code': bank_code
                }
            )
            recipient_data = recipient_response.json()

            if recipient_data['status']:
                return jsonify({
                    'success': True,
                    'recipient_code': recipient_data['data']['recipient_code']
                })
    except Exception as e:
        print(f"Bank validation error: {str(e)}")

    return jsonify({'success': False, 'message': 'Bank account validation failed'})

def get_bank_code(bank_name):
    # Map bank names to Paystack bank codes (e.g., "GT Bank" -> "058")
    bank_codes = {
        "GT Bank": "058",
        "Access Bank": "044",
        "Zenith Bank": "057",
        # Add more banks as needed
    }
    return bank_codes.get(bank_name, "")
@app.route('/paystack-webhook', methods=['POST'])
def paystack_webhook():
    # Verify Paystack signature
    payload = request.get_json()
    secret_hash = os.getenv('PAYSTACK_WEBHOOK_SECRET')  # Add this to your .env
    signature = request.headers.get('x-paystack-signature')

    if not verify_webhook_signature(payload, signature, secret_hash):
        return jsonify({'status': False}), 403

    event = payload['event']
    data = payload['data']

    if event == 'charge.success':
        # Handle successful deposits
        email = data['customer']['email']
        amount = data['amount'] / 100  # Convert to Naira
        
        user = get_user_from_db(email)
        if user:
            user['balance'] += amount
            # Update the transaction status
            for tx in user['transactions']:
                if tx['status'] == 'pending' and tx['service'] == 'Deposit via Virtual Account':
                    tx['status'] = 'success'
                    tx['transaction_id'] = data['reference']
                    break
            
            update_user_in_db(user)
            add_notification(email, f"Your deposit of ₦{amount:,.2f} has been credited")

    return jsonify({'status': True})

def verify_webhook_signature(payload, signature, secret):
    import hashlib
    import hmac
    computed_signature = hmac.new(
        secret.encode('utf-8'),
        str(payload).encode('utf-8'),
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed_signature, signature)



@app.route('/routes')
def list_routes():
    return jsonify({
        'routes': [rule.rule for rule in app.url_map.iter_rules()]
    })
@app.context_processor
def inject_balance():
    if 'user_email' in session:
        user = get_user_from_db(session['user_email'])
        return {'balance': user['balance'] if user else 0}
    return {'balance': 0}


# ==============================================================================
# Run Application
# ==============================================================================

if __name__ == "__main__":
    init_db_pool()
    threading.Thread(target=expose_localhost).start()
    app.run(debug=True, port=5000)