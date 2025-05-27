from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from mailjet_rest import Client
from dateutil import parser
from requests.exceptions import RequestException
from urllib.parse import quote_plus, urlencode, unquote, urlparse, parse_qs
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import requests
import jwt
import time
import socket
import json
import io
import secrets
import random
import bcrypt
import os
import uuid
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


# ===== ENV VARIABLES - START =====

# Check if we're on render.com
IS_PRODUCTION = os.environ.get('RENDER') is not None

# Set proper URL based on environment
if IS_PRODUCTION:
    FRONTEND_URL = "https://gapotravels.onrender.com"
    logger.info("Running in production mode on render.com")
else:
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5000")
    logger.info(f"Running in development mode with URL: {FRONTEND_URL}")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = f"{FRONTEND_URL}/callback/google"
MAILJET_API_KEY = os.getenv("MAILJET_API_KEY")
MAILJET_SECRET_KEY = os.getenv("MAILJET_SECRET_KEY")
MAILJET_TEMPLATE_ID_VERIFY = int(os.getenv('MAILJET_TEMPLATE_ID_VERIFY'))
MAILJET_TEMPLATE_ID_RESET = int(os.getenv('MAILJET_TEMPLATE_ID_RESET'))

# ===== ENV VARIABLES - END =====


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max file size

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if a file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def initialize_supabase(max_retries=3, retry_delay=2):
    """Initialize Supabase client with retry logic"""
    for attempt in range(max_retries):
        try:
            supabase_client = create_client(
                supabase_url=os.getenv('SUPABASE_URL'),
                supabase_key=os.getenv('SUPABASE_KEY')
            )
            service_client = create_client(
                supabase_url=os.getenv('SUPABASE_URL'),
                supabase_key=os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            )
            
            # Test that storage bucket exists or create it
            try:
                # Try to get bucket info to check if it exists
                bucket_info = service_client.storage.get_bucket('avatars')
                logger.info(f"Avatars bucket exists: {bucket_info}")
            except Exception as e:
                # Bucket doesn't exist, create it
                try:
                    # Create bucket with proper format
                    bucket = service_client.storage.create_bucket(
                        id='avatars',  # Use id instead of name
                        options={
                            'public': True,
                            'file_size_limit': 1024 * 1024,  # 1MB
                            'allowed_mime_types': ['image/jpeg', 'image/png', 'image/gif']
                        }
                    )
                    logger.info(f"Created avatars bucket: {bucket}")
                except Exception as bucket_error:
                    logger.error(f"Could not create avatars bucket: {str(bucket_error)}")
                    # Don't raise here, continue without bucket
                    logger.warning("Continuing without avatars bucket - some features may not work")
            
            # Test the connection
            test_response = service_client.table('users').select('count').limit(1).execute()
            if test_response:
                logger.info("Supabase connection test successful")
                return supabase_client, service_client
            raise Exception("Failed to test Supabase connection")
                
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = retry_delay * (attempt + 1)
                logger.warning(f"Supabase initialization attempt {attempt + 1} failed: {str(e)}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Failed to initialize Supabase client after {max_retries} attempts: {str(e)}")
                return None, None

# Initialize Supabase client
try:
    supabase, service_supabase = initialize_supabase()
    if not supabase or not service_supabase:
        raise Exception("Failed to initialize Supabase clients")
except Exception as e:
    logger.error(f"Critical error initializing Supabase: {str(e)}")
    supabase = None
    service_supabase = None

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def get_current_timestamp():
    """Get current UTC timestamp in ISO format"""
    return datetime.now(timezone.utc).isoformat()

class User(UserMixin):
    """User class for Flask-Login"""
    def __init__(self, user_data):
        self.id = user_data.get('id')
        self.first_name = user_data.get('first_name')
        self.last_name = user_data.get('last_name')
        self.email = user_data.get('email')
        self.profile_pic = user_data.get('profile_pic')
        self.created_at = user_data.get('created_at')
        self.provider = user_data.get('provider', 'email')  # Default to 'email' if not set
        self.provider_id = user_data.get('provider_id')
        self.avatar_url = user_data.get('avatar_url')
        self.email_verified = user_data.get('email_verified', False)

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        user_data = service_supabase.table('users').select('*').eq('id', user_id).single().execute()
        if user_data and user_data.data:
            return User(user_data.data)
    except Exception as e:
        logger.error(f"Error loading user: {str(e)}")
    return None


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        user_data = service_supabase.table('users').select('*').eq('id', user_id).single().execute()
        if user_data and user_data.data:
            return User(user_data.data)
    except Exception as e:
        logger.error(f"Error loading user: {str(e)}")
    return None

def check_internet_connection():
    """Check if we can connect to Supabase"""
    try:
        # Try to connect to Supabase
        socket.create_connection(("ljjfcocojtvkbwnsbmxo.supabase.co", 443), timeout=5)
        return True
    except OSError:
        return False

@app.before_request
def check_supabase_connection():
    """Check Supabase connection before each request"""
    if request.endpoint and 'static' not in request.endpoint:
        if not supabase or not service_supabase:
            flash('Database service is unavailable.', 'danger')
            return render_template('500.html'), 500

def test_supabase_connection():
    """Test the Supabase connection and return detailed status"""
    try:
        # Try to fetch a small amount of data to test connection
        response = service_supabase.table('users').select('id').limit(1).execute()
        return True, "Connection successful"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"

@app.route('/test_connection')
def test_connection():
    """Route to test Supabase connection"""
    success, message = test_supabase_connection()
    if success:
        return jsonify({"status": "success", "message": message})
    else:
        return jsonify({"status": "error", "message": message}), 500

# Routes
@app.route('/')
def index():
    if 'user' in session:
        user_data = session['user']

        # Fetch latest user data from users table
        user_result = service_supabase.table('users').select('*').eq('id', user_data['id']).execute()
        if user_result.data:
            user_record = user_result.data[0]
            user_data.update(user_record)

            # Flash for newly created Google account
            if user_record.get('provider') == 'google' and user_record.get('new_google_user'):
                flash(f"Welcome, {user_data.get('first_name', 'User')}! Your Google account was successfully registered.", "success")

                # Set flag to False so it won't flash again
                service_supabase.table('users').update({'new_google_user': False}).eq('id', user_data['id']).execute()

            # Flash for every Google login
            elif user_record.get('provider') == 'google':
                flash(f"Successfully logged in {user_data.get('first_name', 'User')} via Google!", "success")

            # Update session with fresh data
            session['user'] = user_data

        return render_template('index.html', user=user_data)

    return render_template('index.html')

# ===== GOOGLE/SIGNUP ROUTE - START =====

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration route"""
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        profile_pic = request.files.get('profile_pic')
        privacy_agreement = request.form.get('privacy_agreement')

        logger.info(f"Starting signup process for first_name: {first_name}, last_name: {last_name}, email: {email}")

        # Individual field validation
        missing_fields = []
        if not first_name:
            missing_fields.append('First name is required.')
        if not last_name:
            missing_fields.append('Last name is required.')
        if not email:
            missing_fields.append('Email is required.')
        if not password:
            missing_fields.append('Password is required.')

        if missing_fields:
            if len(missing_fields) > 1:
                flash('Fill out all the fields.', 'warning')
            else:
                # Exactly one missing field — flash its message
                flash(missing_fields[0], 'warning')

            # Render the template with previously inputted data to keep the form filled
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        # If all fields are filled but privacy policy not accepted
        if not privacy_agreement:
            flash('You must accept the Privacy Policy to proceed.', 'warning')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        # Password validations (same approach)
        if len(password) < 8:
            flash('Password too short we require 8 characters.', 'warning')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        if not any(c.isupper() for c in password):
            flash('Add at least 1 uppercase letter.', 'warning')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        if not any(c.islower() for c in password):
            flash('Add at least 1 lowercase letter.', 'warning')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        if not any(c.isdigit() for c in password):
            flash('Add at least 1 number.', 'warning')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        if not any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
            flash('Add at least 1 special character.', 'warning')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

        try:
            logger.info("Checking if email exists...")
            existing_email = service_supabase.table('users').select('*').eq('email', email).execute()
            if existing_email.data and len(existing_email.data) > 0:
                flash('This email address is already registered.', 'danger')
                return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

            # Handle profile picture upload
            profile_pic_url = None
            if profile_pic and profile_pic.filename:
                logger.info("Processing profile picture upload...")
                try:
                    profile_pic_url = upload_profile_picture(profile_pic)
                except ValueError as ve:
                    error_msg = str(ve)
                    if "File size exceeds" in error_msg:
                        flash('Profile picture size exceeds (1MB)', 'warning')
                    else:
                        flash('Invalid file type.', 'danger')
                    return redirect(url_for('signup'))
                except Exception as upload_error:
                    logger.error(f'Profile picture upload failed: {str(upload_error)}')
                    # Proceed without profile picture

            # Insert user with email_verified=False
            user_id = str(uuid.uuid4())
            service_supabase.table('users').insert({
                "id": user_id,
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "profile_pic": profile_pic_url,
                "created_at": get_current_timestamp(),
                "email_verified": False,
                "password_hash": generate_password_hash(password)
            }).execute()

            # Generate verification token
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            service_supabase.table('email_verifications').insert({
                "user_id": user_id,
                "token": token,
                "expires_at": expires_at.isoformat(),
                "used": False
            }).execute()

            # Send verification email
            verify_link = url_for('verify_email', token=token, _external=True)
            send_verification_email(email, verify_link)

            flash('Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f'Error during signup: {str(e)}')
            flash('Unable to create your account at this time. Please try again later.', 'danger')
            return render_template('signup.html', first_name=first_name, last_name=last_name, email=email)

    # GET request - empty form
    return render_template('signup.html')

# ===== SIGNUP ROUTE - END =====

# ===== GOOGLE AUTH ROUTE =====

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/login/google')
def login_google():
    try:
        # Get the site URL for the redirect_to parameter
        if os.environ.get('RENDER') or 'render.com' in request.host:
            site_url = 'https://gapotravels.onrender.com'
            logger.info(f"Using production URL for site: {site_url}")
        else:
            site_url = FRONTEND_URL
            logger.info(f"Using development URL for site: {site_url}")
        
        # Use the correct Supabase OAuth URL format
        redirect_url = (
            f"{SUPABASE_URL}/auth/v1/authorize?"
            f"provider=google"
            f"&redirect_to={site_url}/auth-callback/login"
        )
        
        logger.info(f"Google login redirect URL: {redirect_url}")
        return redirect(redirect_url)
    except Exception as e:
        logger.error(f"Google login redirection failed: {str(e)}")
        flash('Failed to initiate Google login.', 'danger')
        return redirect(url_for('login'))

@app.route('/auth-callback/login')
def auth_callback_login():
    # Log information about the request to help with debugging
    logger.info(f"Auth callback received - Host: {request.host}, URL: {request.url}")
    logger.info(f"Request headers: {dict(request.headers)}")
    
    # Add debug info to be passed to the template
    debug_info = {
        'host': request.host,
        'url': request.url,
        'frontend_url': FRONTEND_URL,
        'is_production': IS_PRODUCTION,
        'render_env': os.environ.get('RENDER', 'Not set')
    }
    
    return render_template('auth_callback_login.html', debug_info=debug_info)

@app.route('/callback/google', methods=['POST'])
def google_callback():
    try:
        data = request.get_json()
        access_token = data.get('access_token')

        if not access_token:
            flash("No access token received.", "danger")
            return redirect(url_for('login'))

        headers = {
            "Authorization": f"Bearer {access_token}",
            "apikey": SUPABASE_KEY
        }
        resp = requests.get(f"{SUPABASE_URL}/auth/v1/user", headers=headers)
        if resp.status_code != 200:
            flash("Failed to get user info.", "danger")
            return redirect(url_for('login'))

        user_info = resp.json()
        email = user_info.get('email', '')
        display_name = user_info.get('user_metadata', {}).get('full_name', '') or \
                       user_info.get('user_metadata', {}).get('name', '')
        avatar_url = user_info.get('user_metadata', {}).get('avatar_url', '')
        provider_id = user_info.get('id')

        # Split display name into first and last names
        name_parts = display_name.split()
        first_name = name_parts[0] if name_parts else ''
        last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''

        # Check if user exists in main users table
        user_in_main = service_supabase.table('users').select('*').eq('email', email).execute()

        if not user_in_main.data:
            # Add new user to 'users' table
            dummy_password_hash = generate_password_hash(secrets.token_hex(16))
            now = datetime.utcnow().isoformat()

            service_supabase.table('users').insert({
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "profile_pic": avatar_url,
                "created_at": now,
                "provider": "google",
                "provider_id": provider_id,
                "password_hash": dummy_password_hash,
                "email_verified": True,
                "new_google_user": True
            }).execute()

            # Set flash flag in session for welcome message
            session['new_google_user'] = first_name

            # Refresh user data
            user_in_main = service_supabase.table('users').select('*').eq('email', email).execute()

        main_user_data = user_in_main.data[0]

        # Create a User object and log in
        user = User(main_user_data)
        login_user(user)

        # Update session user data for flash messages
        session['user'] = main_user_data

        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        flash("OAuth error. Try again.", "danger")
        return redirect(url_for('login'))

# ==== GOOGLE AUTH ROUTE ====

# ===== EMAIL LINK FUNCTION - START =====

def send_verification_email(to_email, verify_link):
    mailjet = Client(
        auth=(os.getenv('MAILJET_API_KEY'), os.getenv('MAILJET_SECRET_KEY')),
        version='v3.1'
    )

    data = {
        'Messages': [
            {
                "From": {
                    "Email": os.getenv('MAILJET_FROM_EMAIL'),
                    "Name": os.getenv('MAILJET_FROM_NAME', 'GapoTravels')
                },
                "To": [
                    {
                        "Email": to_email,
                        "Name": to_email
                    }
                ],
                "TemplateID": MAILJET_TEMPLATE_ID_VERIFY,
                "TemplateLanguage": True,
                "Subject": "GapoTravels: Verify Your Email Account",
                "Variables": {
                    "confirmation_link": verify_link,
                    "email_to": to_email
                }
            }
        ]
    }

    result = mailjet.send.create(data=data)
    if result.status_code != 200:
        print("Mailjet error:", result.status_code, result.json())
        
    return result

# ===== EMAIL LINK FUNCTION - END =====

# ===== EMAIL VERIFICATION ROUTE - START =====
@app.route('/verify-email/<token>')
def verify_email(token):
    # Look up the token
    result = service_supabase.table('email_verifications').select('*').eq('token', token).eq('used', False).single().execute()
    data = result.data
    if not data:
        flash('Invalid verification link.', 'danger')
        return redirect(url_for('login'))
    expires_at = parser.isoparse(data['expires_at'])
    if expires_at.tzinfo is None or expires_at.tzinfo.utcoffset(expires_at) is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        flash('Expired verification link.', 'warning')
        return redirect(url_for('login'))
    # Mark user as verified
    service_supabase.table('users').update({'email_verified': True}).eq('id', data['user_id']).execute()
    service_supabase.table('email_verifications').update({'used': True}).eq('id', data['id']).execute()
    flash('Email verified! You can now log in.', 'success')
    return redirect(url_for('login'))

# ===== EMAIL VERIFICATION ROUTE - END =====


# ===== LOGIN/GOOGLE/LOGOUT ROUTE - START =====

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    # Initialize email variable for pre-filling the form if POST fails
    email = ''

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        logger.info(f"Login attempt for email: {email}")

        # Input validation
        missing_fields = []
        if not email:
            missing_fields.append('Email is required.')
        if not password:
            missing_fields.append('Password is required.')

        if missing_fields:
            if len(missing_fields) > 1:
                flash('Please enter both your email and password.', 'warning')
            else:
                flash(missing_fields[0], 'warning')
            return render_template('login.html', email=email)

        try:
            # Fetch user data by email
            user_query = service_supabase.table('users').select('*').eq('email', email).single().execute()
            if not user_query.data:
                logger.error(f"No user found with email: {email}")
                flash('The email you entered does not exist.', 'danger')
                return render_template('login.html', email=email)

            user_data = user_query.data

            # Check password
            if not check_password_hash(user_data['password_hash'], password):
                flash('Incorrect password. Please try again.', 'danger')
                return render_template('login.html', email=email)

            # Check email verification
            if not user_data.get('email_verified', False):
                flash('Verify your email before logging in.', 'warning')
                return render_template('login.html', email=email)

            # Log in the user
            user = User(user_data)
            login_user(user)
            session['user'] = user_data
            flash('Successfully logged in!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Invalid email or password.', 'danger')
            return render_template('login.html', email=email)

    # GET request just render login.html with empty email
    return render_template('login.html', email=email)

@app.route('/logout')
@login_required
def logout():
    """User logout route"""
    try:
        supabase.auth.sign_out()
        session.clear()
        logout_user()
        flash('You have been logged out.', 'success')
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
    return redirect(url_for('index'))

# ===== LOGIN/LOGOUT ROUTE - END =====


# ===== REVIEWs ROUTE - START =====

@app.route('/add_review', methods=['POST'])
@login_required
def add_review():
    content = request.form.get('content', '').strip()
    rating = request.form.get('rating', '').strip()
    destination = request.form.get('destination', '').strip()
    custom_destination = request.form.get('custom_destination', '').strip()

    # Fallback to index page if no referrer is available
    referrer = request.referrer or url_for('index')
    error_redirect = referrer + '#reviews' if '#reviews' not in referrer else referrer

    # Input validations
    if not rating:
        flash('Please select a star rating.', 'warning')
        return redirect(error_redirect)

    if not content:
        flash('Please write your review content.', 'warning')
        return redirect(error_redirect)

    if not destination:
        flash('Please choose a destination.', 'warning')
        return redirect(error_redirect)

    if destination == 'custom' and not custom_destination:
        flash('Please specify a custom destination name.', 'warning')
        return redirect(error_redirect)

    final_destination = custom_destination if destination == 'custom' else destination

    try:
        review_data = {
            "user_id": current_user.id,
            "content": content,
            "rating": int(rating),
            "destination": final_destination,
            "created_at": get_current_timestamp()
        }
        result = supabase.table('reviews').insert(review_data).execute()

        if result.data:
            flash('Review added successfully!', 'success')
            return redirect(url_for('index') + '#reviews')  # <== Always go to index#reviews
        else:
            flash('Error adding review.', 'danger')
            return redirect(error_redirect)

    except Exception as e:
        flash('Error adding review. Please try again.', 'danger')
        return redirect(error_redirect)
    
@app.route('/get_reviews')
def get_reviews():
    """API endpoint to fetch reviews with user info from users table"""
    try:
        # First, fetch all reviews with basic information
        response = service_supabase.table('reviews')\
            .select('*')\
            .order('created_at', desc=True)\
            .execute()

        reviews = response.data if response.data else []
        
        # For each review, fetch the associated user info
        for review in reviews:
            user_id = review.get('user_id')
            if not user_id:
                continue
                
            # Get user from users table
            user_response = service_supabase.table('users')\
                .select('id, first_name, last_name, profile_pic')\
                .eq('id', user_id)\
                .single()\
                .execute()
                
            user = user_response.data if user_response and user_response.data else None
            
            # If user not found, provide default values
            if not user:
                user = {
                    'id': user_id,
                    'first_name': 'Unidentified',
                    'last_name': '',
                    'profile_pic': '/static/images/default-avatar.jpg'
                }
                
            # Add user info to the review
            review['users'] = {
                'id': user.get('id', ''),
                'first_name': user.get('first_name') or 'Unidentified',
                'last_name': user.get('last_name') or '',
                'profile_pic': user.get('profile_pic') or '/static/images/default-avatar.jpg'
            }

        return jsonify(reviews)

    except Exception as e:
        logger.error(f'Error fetching reviews: {str(e)}')
        return jsonify({'error': 'Error fetching reviews'}), 500

@app.route('/delete_review/<review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    """Delete a review"""
    try:
        # Get the review to check ownership
        review = service_supabase.table('reviews').select('*').eq('id', review_id).single().execute()

        if not review.data:
            flash('Review not found.', 'danger')
            return redirect(url_for('index'))

        if review.data['user_id'] != current_user.id:
            flash('You can only delete your own reviews.', 'warning')
            return redirect(url_for('index'))

        # Delete the review
        result = supabase.table('reviews').delete().eq('id', review_id).execute()

        if result.data:
            flash('Review deleted successfully!', 'success')
        else:
            flash('Error deleting review.', 'danger')

    except Exception as e:
        logger.error(f'Error deleting review: {str(e)}')
        flash('Error deleting review.', 'danger')

    return redirect(url_for('index'))

# ===== REVIEWs ROUTE - END =====

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    # Use current_user from Flask-Login instead of session data
    is_google_user = getattr(current_user, 'provider', '') == 'google'  # Detect Google user by provider field
    
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        new_password = request.form.get('new_password', '').strip()
        profile_pic = request.files.get('profile_pic')

        updates = {}
        has_changes = False

        # First name and last name always editable
        if first_name and first_name != current_user.first_name:
            updates['first_name'] = first_name
            has_changes = True

        if last_name and last_name != current_user.last_name:
            updates['last_name'] = last_name
            has_changes = True

        # Profile picture update always allowed
        if profile_pic and profile_pic.filename:
            try:
                profile_pic_url = upload_profile_picture(profile_pic)
                if profile_pic_url:
                    updates['profile_pic'] = profile_pic_url
                    has_changes = True
                    logger.info(f"Profile picture updated to: {profile_pic_url}")
            except ValueError as ve:
                error_msg = str(ve)
                if "File size exceeds" in error_msg:
                    flash('Image too large (max 1MB).', 'danger')
                else:
                    flash('Invalid image type.', 'danger')
                return redirect(url_for('edit_profile'))
            except Exception as upload_error:
                logger.error(f'Profile picture upload failed: {str(upload_error)}')
                flash('Picture upload failed.', 'warning')

        # For normal users only: allow email and password changes
        if not is_google_user:
            if email and email != current_user.email:
                # Check if the new email is already used by another user
                existing_user = service_supabase.table('users').select('*').eq('email', email).execute()
                if existing_user.data and existing_user.data[0]['id'] != current_user.id:
                    flash('Email already taken.', 'danger')
                    return redirect(url_for('edit_profile'))
                updates['email'] = email
                has_changes = True

            # Handle password update with validation
            current_password = request.form.get('current_password', '').strip()
            if new_password:
                # Verify current password is provided and correct
                if not current_password:
                    flash('Current password is required to change password.', 'warning')
                    return redirect(url_for('edit_profile'))

                # Get the current user's password hash from the database
                user_result = service_supabase.table('users').select('password_hash').eq('id', current_user.id).execute()
                if not user_result.data or not user_result.data[0].get('password_hash'):
                    logger.error(f'Could not retrieve password hash for user {current_user.id}')
                    flash('Security verification failed.', 'danger')
                    return redirect(url_for('edit_profile'))

                # Verify the provided current password matches the stored hash
                stored_hash = user_result.data[0]['password_hash']
                if not check_password_hash(stored_hash, current_password):
                    logger.warning(f'Failed password verification attempt for user {current_user.id}')
                    flash('Current password is incorrect.', 'danger')
                    return redirect(url_for('edit_profile'))

                # Password strength validation
                if len(new_password) < 8:
                    flash('Password too short (min 8 chars).', 'warning')
                    return redirect(url_for('edit_profile'))

                if not any(c.isupper() for c in new_password):
                    flash('Add at least 1 uppercase letter.', 'warning')
                    return redirect(url_for('edit_profile'))

                if not any(c.islower() for c in new_password):
                    flash('Add at least 1 lowercase letter.', 'warning')
                    return redirect(url_for('edit_profile'))

                if not any(c.isdigit() for c in new_password):
                    flash('Add at least 1 number.', 'warning')
                    return redirect(url_for('edit_profile'))

                if not any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in new_password):
                    flash('Add at least 1 special character.', 'warning')
                    return redirect(url_for('edit_profile'))

                try:
                    updates['password_hash'] = generate_password_hash(new_password)
                    has_changes = True
                    logger.info(f'Password updated successfully for user {current_user.id}')
                except Exception as e:
                    logger.error(f'Password update error: {str(e)}')
                    flash('Error updating password.', 'danger')
                    return redirect(url_for('edit_profile'))

        else:
            # Google user - ignore email and password changes
            if email and email != current_user.email:
                flash('Email change is not allowed for Google users.', 'warning')
            if new_password:
                flash('Password change is not allowed for Google users.', 'warning')

        # Apply updates if there are any
        if has_changes and updates:
            try:
                logger.info(f"Updating user profile with changes: {updates}")
                # Update appropriate table based on user type
                table_name = 'google_users' if is_google_user else 'users'
                result = service_supabase.table(table_name).update(updates).eq('id', current_user.id).execute()
                if result.data:
                    # Don't need to update session as we're using Flask-Login
                    # We'll reload the user from database on next request
                    flash('Profile updated successfully!', 'success')
                else:
                    flash('Error updating profile.', 'danger')
            except Exception as e:
                logger.error(f'Profile update error: {str(e)}')
                flash('Error updating profile.', 'danger')
        else:
            flash('No changes detected.', 'warning')

        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=current_user, is_google_user=is_google_user)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            if action == 'delete_account':
                user_id = current_user.id

                # Step 1: Find provider_id from google_users for current user
                google_user_result = service_supabase.table('google_users').select('provider_id').eq('user_id', user_id).execute()

                if google_user_result.data:
                    provider_id = google_user_result.data[0]['provider_id']

                    # Step 2: Find all auth users in your 'users' table with the same provider_id
                    auth_users_result = service_supabase.table('users').select('id').eq('provider_id', provider_id).execute()

                    if auth_users_result.data:
                        for auth_user in auth_users_result.data:
                            auth_user_id = auth_user['id']

                            # Delete related data linked to this auth_user_id
                            try:
                                service_supabase.table('reviews').delete().eq('user_id', auth_user_id).execute()
                                service_supabase.table('password_resets').delete().eq('user_id', auth_user_id).execute()
                                service_supabase.table('email_verifications').delete().eq('user_id', auth_user_id).execute()
                            except Exception as related_error:
                                logger.error(f"Error deleting related data for user {auth_user_id}: {str(related_error)}")
                                flash('Error deleting related data. Please contact support.', 'danger')
                                return redirect(url_for('settings'))

                            # Delete the user record itself
                            try:
                                service_supabase.table('users').delete().eq('id', auth_user_id).execute()
                            except Exception as user_error:
                                logger.error(f"Error deleting user {auth_user_id}: {str(user_error)}")
                                flash('Error deleting your account. Please contact support.', 'danger')
                                return redirect(url_for('settings'))

                    # Step 3: Optionally, delete google_users entry for this provider_id
                    try:
                        service_supabase.table('google_users').delete().eq('provider_id', provider_id).execute()
                    except Exception as google_user_error:
                        logger.error(f"Error deleting google_user entry: {str(google_user_error)}")
                        # Not critical, continue

                else:
                    # If no google_users entry found for current user
                    flash('No linked Google account found for deletion.', 'warning')
                    return redirect(url_for('settings'))

                # Step 4: Logout and clear session
                session.clear()
                logout_user()
                flash('Account has been deleted.', 'success')
                return redirect(url_for('index'))

        except Exception as e:
            logger.error(f'Settings update error: {str(e)}')
            flash('Error updating settings.', 'danger')

        return redirect(url_for('settings'))

    return render_template('settings.html', user=session.get('user'))

# ===== PROFILE/SETTINGS ROUTE - END =====


# ===== DESTINATION PAGES ROUTE - START =====

# Routes for destination pages
@app.route('/beaches')
def beaches():
    return render_template('beaches.html')

@app.route('/nature')
def nature():
    return render_template('nature.html')

@app.route('/historical')
def historical():
    return render_template('historical.html')

@app.route('/food')
def food():
    return render_template('food.html')

@app.route('/shopping')
def shopping():
    return render_template('shopping.html')

@app.route('/nightlife')
def nightlife():
    return render_template('nightlife.html')

@app.route('/map')
def map():
    """Interactive map page"""
    return render_template('map.html')

# ===== DESTINATION PAGES ROUTE - END =====


# ===== PASSWORD RESET EMAIL - START =====
# Password Reset Email Function - Edit this function to modify password reset email behavior
def send_reset_email(to_email, reset_link):
    mailjet = Client(
        auth=(os.getenv('MAILJET_API_KEY'), os.getenv('MAILJET_SECRET_KEY')),
        version='v3.1'
    )

    data = {
        'Messages': [
            {
                "From": {
                    "Email": os.getenv('MAILJET_FROM_EMAIL'),
                    "Name": os.getenv('MAILJET_FROM_NAME', 'GapoTravels')
                },
                "To": [
                    {
                        "Email": to_email,
                        "Name": to_email
                    }
                ],
                "TemplateID": MAILJET_TEMPLATE_ID_RESET,
                "TemplateLanguage": True,
                "Subject": "GapoTravels: Reset Your Email Password",  # Can be overridden by template
                "Variables": {
                    "reset_link": reset_link,
                    "email_to": to_email
                }
            }
        ]
    }

    result = mailjet.send.create(data=data)
    if result.status_code != 200:
        print("Mailjet error:", result.status_code, result.json())
    return result

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    email = ''

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Please enter your email address.', 'warning')
            return render_template('forgot_password.html', email=email)

        try:
            user_query = service_supabase.table('users').select('*').eq('email', email).single().execute()
            if not user_query.data:
                flash('Email not found.', 'danger')
                return render_template('forgot_password.html', email=email)

            # Email exists, confirm and redirect to verify_user
            flash('Email confirmed!', 'success')
            return redirect(url_for('verify_user', email=email))

        except Exception as e:
            logger.error(f"Error in forgot_password: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('forgot_password.html', email=email)

    return render_template('forgot_password.html', email=email)

from flask import flash, redirect, render_template, request, url_for
from datetime import datetime, timezone, timedelta
import secrets

@app.route('/verify-user', methods=['GET', 'POST'])
def verify_user():
    email = request.args.get('email') if request.method == 'GET' else request.form.get('email', '').strip()
    first_name = ''
    last_name = ''

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()

        missing_fields = []
        if not first_name:
            missing_fields.append('First name is required.')
        if not last_name:
            missing_fields.append('Last name is required.')

        if missing_fields:
            if len(missing_fields) > 1:
                flash('Please fill in all fields.', 'warning')
            else:
                flash(missing_fields[0], 'warning')
            return render_template('verify_user.html', email=email, first_name=first_name, last_name=last_name)

        try:
            user_query = service_supabase.table('users')\
                .select('*')\
                .eq('email', email)\
                .eq('first_name', first_name)\
                .eq('last_name', last_name)\
                .execute()

            if user_query.data and len(user_query.data) > 0:
                user = user_query.data[0]
                user_id = user['id']

                token = secrets.token_urlsafe(32)
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

                service_supabase.table('password_resets').insert({
                    'user_id': user_id,
                    'token': token,
                    'expires_at': expires_at.isoformat(),
                    'used': False,
                    'created_at': datetime.now(timezone.utc).isoformat()
                }).execute()

                reset_link = url_for('reset_password', token=token, _external=True)
                send_reset_email(email, reset_link)

                flash('Password reset sent to your email.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Name does not match our records.', 'warning')
                return render_template('verify_user.html', email=email, first_name=first_name, last_name=last_name)

        except Exception as e:
            logger.error(f"Error verifying user identity or sending reset link: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('verify_user.html', email=email, first_name=first_name, last_name=last_name)

    return render_template('verify_user.html', email=email, first_name=first_name, last_name=last_name)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Get token data from Supabase
        response = supabase.table('password_resets').select('*').eq('token', token).eq('used', False).execute()
        app.logger.debug(f'Supabase response object: data={response.data}')

        if not response.data:
            flash('Invalid or used reset token.', 'danger')
            return redirect(url_for('forgot_password'))

        reset_record = response.data[0]

        # Check if token is expired
        expires_at = parser.isoparse(reset_record['expires_at'])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            flash('Reset link expired.', 'danger')
            return redirect(url_for('forgot_password'))

        # POST: Handle form submission
        if request.method == 'POST':
            new_password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            app.logger.debug(f'User submitted: password={new_password}, confirm={confirm_password}')

            # Individual field validation
            if not new_password and not confirm_password:
                flash('Please fill out all fields.', 'warning')
                return render_template('reset_password.html', token=token)
            elif not new_password:
                flash('New password is required.', 'warning')
                return render_template('reset_password.html', token=token)
            elif not confirm_password:
                flash('Please confirm your password.', 'warning')
                return render_template('reset_password.html', token=token)

            if new_password != confirm_password:
                flash('Passwords do not match.', 'warning')
                return render_template('reset_password.html', token=token)

            # Password strength checks
            if len(new_password) < 8:
                flash('Password too short (min 8 chars).', 'warning')
                return render_template('reset_password.html', token=token)

            if not any(c.isupper() for c in new_password):
                flash('Add at least 1 uppercase letter.', 'warning')
                return render_template('reset_password.html', token=token)

            if not any(c.islower() for c in new_password):
                flash('Add at least 1 lowercase letter.', 'warning')
                return render_template('reset_password.html', token=token)

            if not any(c.isdigit() for c in new_password):
                flash('Add at least 1 number.', 'warning')
                return render_template('reset_password.html', token=token)

            if not any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in new_password):
                flash('Add at least 1 special character.', 'warning')
                return render_template('reset_password.html', token=token)

            user_id = reset_record['user_id']

            # Check current password
            user_resp = supabase.table('users').select('password_hash').eq('id', user_id).single().execute()
            if not user_resp.data or 'password_hash' not in user_resp.data:
                flash('User not found or invalid user data.', 'danger')
                return render_template('reset_password.html', token=token)

            current_hash = user_resp.data['password_hash']
            if check_password_hash(current_hash, new_password):
                flash('Password cannot be the same as current.', 'warning')
                return render_template('reset_password.html', token=token)

            # Update password
            hashed_password = generate_password_hash(new_password)
            update_resp = supabase.table('users').update({'password_hash': hashed_password}).eq('id', user_id).execute()
            app.logger.debug(f'Password update response: {update_resp}')

            if hasattr(update_resp, 'status_code') and update_resp.status_code not in [200, 204]:
                flash('Failed to update password.', 'danger')
                return render_template('reset_password.html', token=token)

            # Mark token as used
            supabase.table('password_resets').update({'used': True}).eq('id', reset_record['id']).execute()

            # Optional cleanup
            try:
                supabase.table('password_resets')\
                    .delete()\
                    .eq('user_id', user_id)\
                    .eq('used', True)\
                    .neq('id', reset_record['id'])\
                    .execute()
            except Exception as cleanup_err:
                app.logger.warning(f"Cleanup failed: {cleanup_err}")

            flash('Password reset was successful.', 'success')
            return redirect(url_for('login'))

        # GET: Show form
        return render_template('reset_password.html', token=token)

    except Exception as e:
        app.logger.error(f'Error in reset_password: {e}')
        flash('Something went wrong. Try again later.', 'danger')
        return redirect(url_for('forgot_password'))
    
# ===== PASSWORD RESET FLOW - END =====

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

def upload_profile_picture(file):
    """Upload profile picture to Supabase Storage and return the public URL"""
    try:
        # Basic validation
        if not file:
            logger.warning("No file object provided for upload")
            return None
            
        if not file.filename:
            logger.warning("File has no filename")
            return None
        
        logger.info(f"Received file upload request: {file.filename}")
            
        # Check file extension
        if not allowed_file(file.filename):
            logger.error(f"Invalid file type: {file.filename}")
            raise ValueError("Invalid file type")
        
        # Check file size (1MB max)
        MAX_SIZE = 1 * 1024 * 1024  # 1MB
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        logger.info(f"Processing file: {file.filename}, size: {file_size/1024:.2f}KB")
        
        if file_size > MAX_SIZE:
            logger.error(f"File size {file_size/1024:.2f}KB exceeds maximum allowed (1MB)")
            raise ValueError(f"File size exceeds maximum allowed (1MB)")
    except Exception as e:
        logger.error(f"Error in initial file validation: {str(e)}")
        raise
        
    try:
        # Create a unique filename
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        logger.info(f"Generated unique filename: {unique_filename}")
        
        # Process and compress the image using Pillow
        try:
            # Open the image
            image = Image.open(file)
            logger.info(f"Image opened successfully. Mode: {image.mode}, Size: {image.size}")

            # Convert to RGB if image is in RGBA or P mode
            if image.mode in ('RGBA', 'P'):
                image = image.convert('RGB')
                logger.info("Converted image to RGB mode")

            # Calculate new dimensions while maintaining aspect ratio
            MAX_SIZE = (800, 800)  # Maximum dimensions
            image.thumbnail(MAX_SIZE, Image.Resampling.LANCZOS)
            logger.info(f"Resized image to: {image.size}")

            # Create an in-memory bytes buffer
            buffer = io.BytesIO()

            # Save the compressed image to the buffer
            image.save(buffer, format='JPEG', quality=85, optimize=True)
            buffer.seek(0)
            compressed_size = buffer.getbuffer().nbytes

            logger.info(f"Original size: {file_size/1024:.2f}KB, Compressed size: {compressed_size/1024:.2f}KB")
            
            # Upload compressed file to Supabase Storage
            try:
                result = service_supabase.storage.from_('avatars').upload(
                    unique_filename,
                    buffer.getvalue(),
                    {'content-type': 'image/jpeg'}  # Always JPEG after compression
                )
                logger.info(f"Upload result: {result}")
            
                # Get public URL
                public_url = service_supabase.storage.from_('avatars').get_public_url(unique_filename)
                logger.info(f"Profile picture uploaded successfully: {public_url}")
                
                return public_url
            except Exception as upload_error:
                logger.error(f"Supabase storage upload error: {str(upload_error)}")
                raise
                
        except Exception as image_error:
            logger.error(f"Image processing error: {str(image_error)}")
            raise
            
    except Exception as e:
        logger.error(f"Error uploading profile picture: {str(e)}")
        raise e

#Run the app
if __name__ == "__main__":
    app.run(debug=True)