import os
import uuid
from flask import Flask, render_template, redirect, url_for, flash, session, request, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, send, emit
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
import paypalrestsdk
from dotenv import load_dotenv
import psycopg2  # Added for PostgreSQL support

# Initialize Flask application
app = Flask(__name__)
load_dotenv()

# ============================================
# Configuration (Railway-Specific Changes)
# ============================================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')

# Database configuration for Railway (PostgreSQL)
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'static/'

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# ============================================
# Initialize Extensions
# ============================================
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # Added CORS support
mail = Mail(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# PayPal configuration
paypalrestsdk.configure({
    "mode": os.getenv('PAYPAL_MODE', 'sandbox'),
    "client_id": os.getenv('PAYPAL_CLIENT_ID'),
    "client_secret": os.getenv('PAYPAL_CLIENT_SECRET')
})

# ============================================
# Database Models
# ============================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)

class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    game_id = db.Column(db.String(100), nullable=False)
    server = db.Column(db.String(100), nullable=False)
    tournament_no = db.Column(db.String(100), nullable=False)
    clan_name = db.Column(db.String(100), nullable=False)

# ============================================
# Authentication Routes
# ============================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('home'))
        flash('Login unsuccessful. Please check your email and password', 'danger')
    
    return render_template('login.html')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please login', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# ============================================
# Main Application Routes
# ============================================
# Change from:

# To:
@app.route("/")
def index():  # Rename the function to 'index'
    return render_template('index.html')
@app.route("/")
def home():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template('new.html')

@app.route("/games")
def games():
    return render_template('games.html')

@app.route("/contact")
def contact():
    return render_template('contact.html')

# ============================================
# Protected Routes (Require Login)
# ============================================
@app.route('/community')
@login_required
def community():
    return render_template('community.html', username=current_user.username)

@app.route('/forum')
@login_required
def forum():
    return render_template('forum.html', username=current_user.username)

@app.route('/leader')
@login_required
def leader_board():
    return render_template('leader.html')

@app.route('/tournament')
@login_required
def tournament():
    return render_template('tournament.html', username=current_user.username)

@app.route('/upload-image', methods=['POST'])
@login_required
def upload_image():
    if 'file' not in request.files:
        return 'No file part'
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    
    if file:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'hero.webp'))
        return redirect(url_for('tournament'))

# ============================================
# Chat Functionality (SocketIO)
# ============================================
connected_users = set()
messages = []

@app.route('/chat_users')
def chat_users():
    return jsonify({'count': len(connected_users)})

@socketio.on('message')
def handle_message(data):
    messages.append(data)
    send(data, broadcast=True)

@socketio.on('typing')
def handle_typing(user):
    emit('typing', user, broadcast=True)

@socketio.on('userConnected')
def handle_user_connected():
    connected_users.add(request.sid)
    emit('loadMessages', messages, to=request.sid)
    emit('connectedUsers', len(connected_users), broadcast=True)

@socketio.on('userDisconnected')
@socketio.on('disconnect')
def handle_disconnect():
    connected_users.discard(request.sid)
    emit('connectedUsers', len(connected_users), broadcast=True)

# ============================================
# Payment System
# ============================================
@app.route('/product')
def product():
    return render_template('product.html')

@app.route('/pay', methods=['POST'])
def pay():
    selected_pdfs = request.form.getlist('pdfs')
    pdf_prices = {"pdf001": 10.00, "pdf002": 10.00}

    if not selected_pdfs:
        flash('Please select at least one PDF.', 'danger')
        return redirect(url_for('product'))

    total_amount = sum(pdf_prices[pdf] for pdf in selected_pdfs)

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {"payment_method": "paypal"},
        "redirect_urls": {
            "return_url": url_for('payment_success', selected_pdfs=",".join(selected_pdfs), _external=True),
            "cancel_url": url_for('payment_cancel', _external=True)
        },
        "transactions": [{
            "item_list": {
                "items": [{
                    "name": f"{len(selected_pdfs)} PDF(s) Purchase",
                    "sku": ",".join(selected_pdfs),
                    "price": str(total_amount),
                    "currency": "USD",
                    "quantity": 1
                }]
            },
            "amount": {
                "total": str(total_amount),
                "currency": "USD"
            },
            "description": "Purchase of selected handwritten notes PDFs."
        }]
    })

    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                return redirect(link.href)
    return "Payment creation failed. Please try again."

@app.route('/payment_success')
def payment_success():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    selected_pdfs = request.args.get('selected_pdfs').split(',')

    if not payment_id or not payer_id or not selected_pdfs:
        return "Invalid request parameters."

    try:
        payment = paypalrestsdk.Payment.find(payment_id)
        if payment.execute({"payer_id": payer_id}):
            transaction = payment.transactions[0]
            send_confirmation_email(
                payment.payer.payer_info.email,
                transaction.amount.total,
                transaction.amount.currency,
                payment.id,
                selected_pdfs
            )
            download_links = [url_for('download_pdf', transaction_id=payment.id, pdf_id=pdf_id) for pdf_id in selected_pdfs]
            return render_template('success.html', download_links=download_links)
        return "Payment execution failed. Please try again."
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/download/<transaction_id>/<pdf_id>')
def download_pdf(transaction_id, pdf_id):
    pdf_files = {
        "pdf001": "note1.pdf",
        "pdf002": "note2.pdf",
    }
    file_name = pdf_files.get(pdf_id)
    if not file_name:
        return "File not found."
    
    file_path = os.path.join('static/pdfs', file_name)
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return "File not found."

@app.route('/payment_cancel')
def payment_cancel():
    return render_template('failed.html')

# ============================================
# Admin Section
# ============================================
@app.route('/login_admin', methods=['POST'])
def login_admin():
    pin = request.form.get('pin')
    if pin == '12345':  # Replace with your actual PIN
        session['is_admin'] = True
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('home'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('home'))
    
    notifications = [
        {'message': 'New user registered: JohnDoe', 'date': '2024-08-29'},
        {'message': 'Content approval pending for post #123', 'date': '2024-08-28'},
    ]
    users = User.query.all()
    registrations = Registration.query.all()
    return render_template('admin_dashboard.html', notifications=notifications, users=users, registrations=registrations)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/send_announcement', methods=['POST'])
@login_required
def send_announcement():
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    subject = request.form.get('subject')
    message = request.form.get('message')
    
    if subject and message:
        users = User.query.all()
        emails = [user.email for user in users]
        msg = Message(subject, sender=os.getenv('MAIL_USERNAME'), recipients=emails)
        msg.body = message
        mail.send(msg)
        flash('Announcement sent to all users', 'success')
    else:
        flash('Please provide both subject and message', 'danger')
    return redirect(url_for('admin_dashboard'))

# ============================================
# Registration System
# ============================================
@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    game_id = request.form['game_id']
    server = request.form['server']
    tournament_no = request.form['tournament_no']
    clan_name = request.form['clan_name']
    
    player_id = str(uuid.uuid4())
    registration = Registration(
        player_id=player_id,
        name=name,
        email=email,
        game_id=game_id,
        server=server,
        tournament_no=tournament_no,
        clan_name=clan_name
    )
    db.session.add(registration)
    db.session.commit()

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {"payment_method": "paypal"},
        "redirect_urls": {
            "return_url": url_for('payment_successful', player_id=player_id, _external=True),
            "cancel_url": url_for('payment_cancelled', _external=True)
        },
        "transactions": [{
            "item_list": {
                "items": [{
                    "name": f"Tournament Registration #{tournament_no}",
                    "sku": "tournament",
                    "price": "10.00",
                    "currency": "USD",
                    "quantity": 1
                }]
            },
            "amount": {
                "total": "10.00",
                "currency": "USD"
            },
            "description": f"Registration for Tournament #{tournament_no} by {name} (Clan: {clan_name})"
        }]
    })

    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                return redirect(link.href)
    return "Error while processing the payment"

@app.route('/payment-success')
def payment_successful():
    player_id = request.args.get('player_id')
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)
    if payment.execute({"payer_id": payer_id}):
        registration = Registration.query.filter_by(player_id=player_id).first()
        if registration:
            send_confirmation_email_registration(
                registration.email,
                registration.name,
                registration.player_id,
                registration.tournament_no
            )
            return f"Payment completed successfully! Your Player ID: {player_id}"
        return "Registration information not found."
    return "Payment failed!"

@app.route('/payment-cancelled')
def payment_cancelled():
    return "Payment was cancelled."

@app.route('/delete-registration/<int:id>', methods=['POST'])
def delete_registration(id):
    registration = Registration.query.get_or_404(id)
    db.session.delete(registration)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# ============================================
# Newsletter Subscription
# ============================================
@app.route('/subscription', methods=['GET', 'POST'])
def subscription():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required', 'danger')
            return redirect(url_for('subscription'))

        if Subscriber.query.filter_by(email=email).first():
            flash('This email is already subscribed', 'info')
        else:
            new_subscriber = Subscriber(email=email)
            db.session.add(new_subscriber)
            db.session.commit()
            send_confirmation_email_for_newsletter(email)
            flash('Thank you for subscribing!', 'success')
        return redirect(url_for('home'))

    return render_template('subscription.html')

# ============================================
# Helper Functions
# ============================================
def send_confirmation_email(email, amount, currency, transaction_id, selected_pdfs):
    download_links = [url_for('download_pdf', transaction_id=transaction_id, pdf_id=pdf_id, _external=True) for pdf_id in selected_pdfs]
    
    msg = Message('Payment Confirmation',
                sender=os.getenv('MAIL_USERNAME'),
                recipients=[email])
    msg.body = f"""Thank you for your purchase.

Payment Details:
Amount: {amount} {currency}
Transaction ID: {transaction_id}

Download links:
""" + "\n".join(download_links) + "\n\nBest regards,\nYour Company"
    mail.send(msg)

def send_confirmation_email_registration(email, name, player_id, tournament_no):
    msg = Message(
        "Tournament Registration Confirmation",
        sender=os.getenv('MAIL_USERNAME'),
        recipients=[email]
    )
    msg.body = f"""Dear {name},

Thank you for registering for Tournament #{tournament_no}!

Your registration has been successfully processed.
Your Player ID: {player_id}

We look forward to seeing you in the tournament.

Best regards,
Tournament Organizers"""
    mail.send(msg)

def send_confirmation_email_for_newsletter(email):
    msg = Message(
        'Subscription Confirmation',
        sender=os.getenv('MAIL_USERNAME'),
        recipients=[email]
    )
    msg.body = 'Thank you for subscribing to our newsletter!'
    mail.send(msg)

# ============================================
# Application Entry Point
# ============================================
def create_tables():
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Error creating database tables: {str(e)}")

if __name__ == "__main__":
    create_tables()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)
else:
    create_tables()