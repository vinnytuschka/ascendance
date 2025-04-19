from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from config import Config
# from flask_wtf.csrf import CSRFProtect
import stripe
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from models import db, User
from dotenv import load_dotenv
import re

# Load .env file
load_dotenv()

# ----------------------------------------
# Initialize Flask App
# ----------------------------------------

app = Flask(__name__)
app.config.from_object(Config)  # Load configuration from config.py

# ----------------------------------------
# Initialize Extensions
# ----------------------------------------

db.init_app(app)
mail = Mail(app)
# csrf = CSRFProtect(app)

# Stripe API key
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Secret Key check (needed for sessions, CSRF, tokens)
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY is not set in your config.")

# Token generator for password reset and email verification
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Home route to display to logged in users
@app.route('/')
@login_required
def home():
    user = User.query.get(session["user_id"])
    users = User.query.all()
    return render_template('home.html', user=user, users=users)

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():

    users = User.query.all()

    if request.method == "POST":
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('pass_confirm')

        # Check if any field is missing
        missing_fields = []
        if not username:
            missing_fields.append("Username")
        if not email:
            missing_fields.append("Email")
        if not password:
            missing_fields.append("Password")
        if not confirm:
            missing_fields.append("Confirm Password")

        if missing_fields:
            flash(f"Missing Information: {', '.join(missing_fields)}", "danger")
            return render_template("sign_up.html")

        # Validate email format
        if not validate_email(email):
            flash("Invalid email format. Please enter a valid email.", "danger")
            return render_template("sign_up.html")

        # Check if passwords match
        if password != confirm:
            flash("Passwords do not match!", "danger")
            return render_template("sign_up.html")

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose another.", "danger")
            return render_template("sign_up.html")

        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email already registered. Try logging in or resetting your password.", "danger")
            return render_template("sign_up.html")

        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)
        db.session.commit()

        # Log the user in by storing their user_id in the session
        session["user_id"] = new_user.id

        # Send confirmation email
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirm your email', sender='noreply@yourapp.com', recipients=[email])
        msg.body = f'Click to verify your account: {link}'
        mail.send(msg)

        # Redirect to login page after successful registration
        flash("Account created! Please check your email to confirm your account.", "success")
        return redirect(url_for('login'))

    return render_template("sign_up.html", users=users)

# Helper function for sign-up to validate e-mail
def validate_email(email):
    """Validate email using regex"""
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(email_regex, email) is not None

# Login route for current users
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect("/")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session["user_id"] = user.id  # Store user in session
            session["username"] = user.username
            return redirect("/")
        else:
            flash("Invalid username or password!")
            return render_template("login.html")

    return render_template("login.html")

#Logout route for current users
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():

    user_id = session["user_id"]

    if request.method == "POST":
        if 'user_id' in session:
            session.clear()
        return redirect(url_for('login'))
    return render_template("logout.html", user_id = user_id)

# Forgot Password Route
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.id, salt='password-reset')  # Use user.id instead of email
            link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Link',
                          sender='noreply@yourapp.com',
                          recipients=[email])
            msg.body = f'Click the link to reset your password: {link}'
            mail.send(msg)
            flash("If that email is in our system, we sent a reset link.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

# Reset Password Route (for forgotten passwords) --- Need to figure out confirmation email
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):  # Corrected function name to match URL
    try:
        user_id = s.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiry
    except Exception as e:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        if new_password != confirm_password:
            flash("Passwords do not match.", "warning")
            return render_template("reset_password.html", token=token)

        user.set_password(new_password)
        db.session.commit()
        flash("Password successfully reset!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

@app.route("/confirm_email/<token>")
def confirm_email(token):
    try:
        # Try to load the email from the token, with a 1-day expiration time
        email = s.loads(token, salt='email-confirm', max_age=86400)
    except BadSignature:
        # Invalid signature
        flash("The confirmation link is invalid.", "danger")
        return redirect(url_for("sign_up"))
    except SignatureExpired:
        # Link expired
        flash("The confirmation link has expired. Please request a new one.", "danger")
        return redirect(url_for("sign_up"))

    # Query the user by email
    user = User.query.filter_by(email=email).first()

    if user:
        # If user is found, mark them as verified
        if user.verified:
            flash("Your email is already verified!", "info")
        else:
            user.verified = True
            db.session.commit()
            flash("Email verified successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    # If no user is found with the provided email
    flash("User not found. Please sign up first.", "danger")
    return redirect(url_for("sign_up"))

# Resets current users password
@app.route("/change_password/<int:id>", methods=["GET", "POST"])
@login_required
def change_password(id):
    user = User.query.get_or_404(id)

    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        # First, check current password
        if not user.check_password(current_password):
            return render_template("change_password.html", user=user, error="Current password is incorrect.")

        # Then, check if new and confirm passwords match
        if new_password != confirm_password:
            return render_template("change_password.html", user=user, passwords_mismatch=True)

        # If both checks pass, update the password
        user.set_password(new_password)
        db.session.commit()
        flash("Password Changed!", "success")
        return redirect(url_for("home"))

    return render_template("change_password.html", user=user)

# Makes payment for current user
@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    if request.method == "POST":
        try:
            amount = request.form["amount"]

            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[
                    {
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': 'Payment for Product/Service',
                            },
                            'unit_amount': int(amount) * 100,
                        },
                        'quantity': 1,
                    },
                ],
                mode='payment',
                success_url=url_for('payment_success', _external=True),
                cancel_url=url_for('payment_cancel', _external=True),
            )

            return redirect(session.url, code=303)

        except Exception as e:
            return f"An error occurred: {e}", 400

    return render_template("payment.html")

@app.route("/payment_success")
def payment_success():
    return render_template("payment_success.html")

@app.route("/payment_cancel")
def payment_cancel():
    return render_template("payment_cancel.html")

# Update user profile information
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session["user_id"])

    if not user:
        return "User not found.", 404

    if request.method == 'POST':
        # Get form data
        firstname = request.form.get('first_name')
        lastname = request.form.get('last_name')
        email = request.form.get('email')
        address = request.form.get('address')
        phonenumber = request.form.get('phone_number')

        # Validate input
        if not all([firstname, lastname, email, address, phonenumber]):
            flash("Missing profile information. Please complete all fields.", "error")
            return render_template('profile.html', user=user)

        # Update user
        user.first_name = firstname
        user.last_name = lastname
        user.email = email
        user.address = address
        user.phone_number = phonenumber

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# Settings page for current users
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user_id = session["user_id"]
    return render_template('settings.html', user_id = user_id)

# Deletes Users Account
@app.route('/delete/<int:id>', methods=["GET", "POST"])
@login_required
def delete_user(id):
    user_to_delete = User.query.get(id)

    # If the user is not found, return a 404 error
    if not user_to_delete:
        return "User not found.", 404

    if request.method == "POST":
        db.session.delete(user_to_delete)
        db.session.commit()
        session.clear()  # Clear the session to log the user out
        return redirect('/login')  # Redirect to login page after deletion

    # Render delete confirmation page if it's a GET request
    return render_template("delete_user.html", user=user_to_delete)

# Static page rendering
@app.route('/<page>')
@login_required
def static_page(page):
    allowed_pages = ['wiki', 'e-commerce', 'social_media', 'applications']
    if page in allowed_pages:
        return render_template(f'{page}.html')
    return "Page not found", 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False)
