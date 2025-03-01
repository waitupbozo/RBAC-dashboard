from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import timedelta, datetime
import os
import re
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Set these environment variables in your OS or use a config file in production.
app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY', 'your_site_key')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY', 'your_secret_captcha_key')

# MySQL configurations – update these with your MySQL credentials
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'your_mysql_userid'
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
app.config['MYSQL_DB'] = 'flask_app'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Returns rows as dictionaries

# Initialize MySQL and Bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Set session lifetime
app.permanent_session_lifetime = timedelta(minutes=30)  # Sessions expire after 30 minutes

# Route to serve the registration page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle user registration
@app.route('/register', methods=['POST'])
def register():
    # Retrieve form data
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    print("Received registration data:", username, email, role)  # Debug log

    # Basic backend validation
    if not username or not email or not password or not role:
        flash('Please fill in all required fields.', 'danger')
        return redirect(url_for('index'))
    
    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    print("Hashed password:", hashed_password)  # Debug log

    # Insert user data into MySQL
    cur = mysql.connection.cursor()
    try:
        query = "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)"
        cur.execute(query, (username, email, hashed_password, role))
        mysql.connection.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('index', show='login'))
    except Exception as e:
        mysql.connection.rollback()
        flash('Error occurred during registration. Email might already be registered.', 'danger')
        print(f"Error: {e}")
    finally:
        cur.close()

    return redirect(url_for('index'))

# Route to handle user login
@app.route('/login', methods=['POST'])
def login():
    # Initialize or retrieve login attempts from session
    if 'login_attempts' not in session:
        session['login_attempts'] = 0

    # Check for lockout condition: if attempts exceed 5 and lockout period (15 minutes) not elapsed
    if session.get('login_attempts', 0) >= 5:
        lockout_time_str = session.get('lockout_time')
        if lockout_time_str:
            lockout_time = datetime.fromisoformat(lockout_time_str)
            # Remove timezone information if present
            lockout_time = lockout_time.replace(tzinfo=None)
            if (datetime.utcnow() - lockout_time).total_seconds() < 900:
                flash("Too many failed login attempts. Please try again after 15 minutes.", "danger")
                return redirect(url_for('index', show='login'))
            else:
                session['login_attempts'] = 0
                session.pop('lockout_time', None)

    # Retrieve and validate inputs
    email = request.form.get('login-email', '').strip()
    password = request.form.get('login-password', '')
    
    # Basic validation: ensure non-empty and valid email format
    if not email or not password:
        flash("Please fill all required fields.", "danger")
        return redirect(url_for('index', show='login'))
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for('index', show='login'))

    # Verify reCAPTCHA response
    captcha_response = request.form.get('g-recaptcha-response')
    recaptcha_secret = app.config.get('RECAPTCHA_SECRET_KEY')
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': recaptcha_secret,
        'response': captcha_response,
        'remoteip': request.remote_addr
    }
    captcha_verification = requests.post(captcha_verify_url, data=payload).json()
    if not captcha_verification.get('success'):
        flash("Captcha verification failed. Please try again.", "danger")
        return redirect(url_for('index', show='login'))

    # Fetch the user from the database
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    # If user is found and password is correct, reset login_attempts and log in
    if user and bcrypt.check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session.permanent = True  # Set session lifetime as configured
        # Reset login attempts after successful login
        session['login_attempts'] = 0
        flash('Login successful!', 'success')
        # Role-based redirection (for example, admin vs. regular user)
        if user['role'].lower() == 'admin':
            return redirect(url_for('admin_panel'))
        else:
            return redirect(url_for('dashboard'))
    else:
        # Increment failed login attempts and set lockout time if threshold reached
        session['login_attempts'] = session.get('login_attempts', 0) + 1
        if session['login_attempts'] >= 5:
            session['lockout_time'] = datetime.utcnow().isoformat()
        flash('Invalid email or password. Please try again.', 'danger')
        return redirect(url_for('index', show='login'))

# Decorator to require login for certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('index', show='login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to require admin role for certain routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Route to handle user dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    print("Rendering dashboard for user:", session['username'])  # Debug log
    return render_template('dashboard.html', username=session['username'])

# Route to handle admin panel
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.close()
    print("Rendering admin panel for user:", session['username'])  # Debug log
    return render_template('admin.html', users=users)

# Route to handle user deletion
@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin_panel'))

# Route to handle user account management
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user_id = session.get('user_id')
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get('username')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate required fields
        if not username or not email:
            flash("Username and email cannot be empty.", "danger")
            return redirect(url_for('account'))
        
        # Fetch current user details from DB
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        
        # Check if any details have changed
        if (username == user['username'] and email == user['email'] and
            not current_password and not new_password and not confirm_password):
            flash("No changes detected.", "warning")
            return redirect(url_for('account'))
        
        # If user wants to update password, validate the current password and match new passwords
        if new_password:
            if not current_password:
                flash("Please enter your current password to change your password.", "danger")
                return redirect(url_for('account'))
            if not bcrypt.check_password_hash(user['password'], current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for('account'))
            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return redirect(url_for('account'))
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        else:
            hashed_password = user['password']  # Keep existing password if no new password is provided
        
        # Update user details in the database
        try:
            query = "UPDATE users SET username = %s, email = %s, password = %s WHERE id = %s"
            cur.execute(query, (username, email, hashed_password, user_id))
            mysql.connection.commit()
            flash("Account details updated successfully.", "success")
            session['username'] = username  # Update session if username changed
        except Exception as e:
            mysql.connection.rollback()
            flash("An error occurred while updating your account.", "danger")
            print("Update error:", e)
        finally:
            cur.close()
        return redirect(url_for('account'))
    
    else:
        # For GET request, fetch the user's current details
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        return render_template('account.html', user=user)

# Route to handle user logout
@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
