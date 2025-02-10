import os
import base64
import uuid
import datetime
import mysql.connector
import bcrypt
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_mail import Mail, Message
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize the TRANSACTIONS dictionary in app.config
app.config['TRANSACTIONS'] = {}

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_ADDRESS')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
mail = Mail(app)

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': os.getenv('DB_PASSWORD'),
    'database': 'user_db'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Asymmetric Encryption (RSA)
def asymmetric_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

# Asymmetric Decryption (RSA)
def asymmetric_decrypt(ciphertext, private_key):
    ciphertext = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# Generate OTP
def generate_otp(length=6):
    return ''.join([str(uuid.uuid4().int % 10) for _ in range(length)])

# Home Route
@app.route('/')
def home():
    return render_template('user.html')

# Sign Up Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        phone_number = request.form['phone_number']

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            conn = get_db_connection()
            cursor = conn.cursor()

            query_user = """
            INSERT INTO user1 (email, password, username, phone_number) 
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query_user, (email, hashed_password.decode('utf-8'), username, phone_number))
            conn.commit()

            query_balance = """
            INSERT INTO balance (username, balance) 
            VALUES (%s, %s)
            """
            cursor.execute(query_balance, (username, 1000))
            conn.commit()

            flash('Sign up successful!', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Email or Username already exists!", "danger")
        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", 'danger')
        finally:
            cursor.close()
            conn.close()
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM user1 WHERE username = %s", (username,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('pay'))
            flash('Invalid username or password.', 'danger')
        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", 'danger')
        finally:
            cursor.close()
            conn.close()
    return render_template('login.html')

# Balance Route
@app.route('/balance')
def balance():
    if 'username' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT balance FROM balance WHERE username = %s", (session['username'],))
        current_user = cursor.fetchone()
        user_balance = current_user['balance'] if current_user else 0
    except mysql.connector.Error as err:
        flash(f"Database Error: {err}", 'danger')
        return redirect(url_for('pay'))
    finally:
        cursor.close()
        conn.close()
    return render_template('balance.html', balance=user_balance)

# Payment Page Route
@app.route('/pay', methods=['GET', 'POST'])
def pay():
    if 'username' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))

    users = []
    balance = 0

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Fetch all users except the logged-in user
        cursor.execute("SELECT username, phone_number, email FROM user1 WHERE username != %s ORDER BY username ASC", (session['username'],))
        users = cursor.fetchall()

        # Fetch current user balance
        cursor.execute("SELECT balance FROM balance WHERE username = %s", (session['username'],))
        current_user = cursor.fetchone()
        balance = current_user['balance'] if current_user else 0

        if request.method == 'POST':
            to_user = request.form.get('to_user')
            amount = float(request.form.get('amount'))

            if amount <= 0:
                flash('Please enter a positive amount.', 'danger')
                return render_template('pay.html', users=users, balance=balance, current_user=session['username'])

            # Get recipient's email
            cursor.execute("SELECT email FROM user1 WHERE username = %s", (to_user,))
            recipient_data = cursor.fetchone()

            if not recipient_data:
                flash("Recipient not found!", "danger")
                return render_template('pay.html', users=users, balance=balance, current_user=session['username'])

            recipient_email = recipient_data['email']

            if balance < amount:
                flash('Insufficient balance.', 'danger')
                return render_template('pay.html', users=users, balance=balance, current_user=session['username'])

            # Transaction logic using RSA encryption
            sender_private_key, sender_public_key = generate_rsa_keys()
            # Store keys securely (e.g., in database or secure storage)

            # Get recipient's public key (replace with actual retrieval method)
            # For now, generating a new key for the recipient, but this should be retrieved securely
            receiver_private_key, receiver_public_key = generate_rsa_keys()

            otp = generate_otp()
            encrypted_amount = asymmetric_encrypt(str(amount), receiver_public_key)

            transaction_id = str(uuid.uuid4())

            transaction_data = {
                'encrypted_amount': encrypted_amount,
                'otp': otp,
                'to_user': to_user,
                'amount': amount,  # Store the original amount
                'recipient_email': recipient_email,
                'sender_username': session['username'],
                'transaction_id': transaction_id,
                'receiver_private_key': receiver_private_key,  # Store receiver's private key (INSECURE - for demonstration only)
            }

            app.config['TRANSACTIONS'][transaction_id] = transaction_data

            msg = Message('Secure Transaction OTP', sender=app.config['MAIL_USERNAME'], recipients=[recipient_email])
            # Send encrypted amount in the email
            msg.body = f"""
            Dear User,

            A secure transaction of {encrypted_amount} has been initiated by {session['username']}.

            OTP: {otp}

            Click the link below to complete the transaction:
            {url_for('complete_transaction', transaction_id=transaction_id, _external=True)}

            Transaction ID:{transaction_id}
            Best regards,
            Secure Transaction Service
            """
            try:
                mail.send(msg)
                flash("Payment initiated. Check recipient's email for OTP.", "success")
            except Exception as e:
                flash(f"Payment initiated, but email not sent: {str(e)}", "warning")

            return render_template('pay.html', users=users, balance=balance, current_user=session['username'])

        return render_template('pay.html', users=users, balance=balance, current_user=session['username'])

    except mysql.connector.Error as err:
        flash(f"Database Error: {err}", 'danger')
    finally:
        cursor.close()
        conn.close()

    return render_template('pay.html', users=users, balance=balance, current_user=session['username'])

# Route for completing the transaction using OTP
@app.route('/complete_transaction/<transaction_id>', methods=['GET', 'POST'])
def complete_transaction(transaction_id):
    transaction = app.config['TRANSACTIONS'].get(transaction_id)
    if not transaction:
        flash('Invalid transaction ID.', 'danger')
        return render_template('complete_transaction.html', transaction_id=transaction_id, recipient_email=None,
                               decrypted_amount=None)

    if request.method == 'POST':
        otp_input = request.form['otp']
        if otp_input != transaction['otp']:
            flash('Transaction Failed: Incorrect OTP.', 'danger')
            return render_template('complete_transaction.html', transaction_id=transaction_id,
                                   recipient_email=transaction['recipient_email'], decrypted_amount=None)

        # Decrypt the amount
        receiver_private_key = transaction['receiver_private_key']
        decrypted_amount = float(asymmetric_decrypt(transaction['encrypted_amount'], receiver_private_key))

        to_user = transaction['to_user']
        amount = transaction['amount']
        sender_username = transaction['sender_username']

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Start the transaction
            conn.start_transaction()

            # Deduct amount from sender
            cursor.execute("UPDATE balance SET balance = balance - %s WHERE username = %s", (amount, sender_username))

            # Add amount to recipient
            cursor.execute("UPDATE balance SET balance = balance + %s WHERE username = %s", (amount, to_user))

            # Save transaction history
            date = datetime.datetime.now().strftime('%Y-%m-%d')
            cursor.execute("INSERT INTO transaction_history (username, date, amount, to_user) VALUES (%s, %s, %s, %s)",
                           (sender_username, date, amount, to_user))
            cursor.execute("INSERT INTO transaction_history (username, date, amount, to_user) VALUES (%s, %s, %s, %s)",
                           (to_user, date, amount, sender_username))

            # Commit the transaction
            conn.commit()
            flash(f'Transaction Successful! Amount: {decrypted_amount} transferred to {to_user}.', 'success')

            # Remove the transaction from the app.config
            del app.config['TRANSACTIONS'][transaction_id]

            return render_template('complete_transaction.html', transaction_id=transaction_id,
                                   recipient_email=transaction['recipient_email'],
                                   decrypted_amount=decrypted_amount)

        except mysql.connector.Error as err:
            conn.rollback()
            flash(f"Database Error: {err}", 'danger')
            return render_template('complete_transaction.html', transaction_id=transaction_id,
                                   recipient_email=transaction['recipient_email'], decrypted_amount=None)

        finally:
            cursor.close()
            conn.close()

    return render_template('complete_transaction.html', transaction_id=transaction_id, recipient_email=None,
                           decrypted_amount=None)

# Transaction History Route
@app.route('/transaction_history')
def transaction_history():
    if 'username' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))
    transactions = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM transaction_history WHERE username = %s ORDER BY date DESC", (session['username'],))
        transactions = cursor.fetchall()
    except mysql.connector.Error as err:
        flash(f"Database Error: {err}", 'danger')
    finally:
        cursor.close()
        conn.close()
    return render_template('transaction_history.html', transactions=transactions)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)