# Manage partial imports
from flask_login import login_required, current_user, login_user, LoginManager, UserMixin, logout_user
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from dotenv import load_dotenv
from functools import wraps

# Manage full imports
import crypto_methods
import json
import stripe
import os

# Configure Flask app
app = Flask("Swupel Primain Service")
app.config['SECRET_KEY'] = crypto_methods.PASSWORD
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Generate a serializer object with the app's secret key
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_verification_token(email):
    """Generates a verification token for a given email.

    Args:
        email (str): The email address to generate a token for.

    Returns:
        str: The generated token.
    """
    return s.dumps(email, salt=app.config['SECRET_KEY'])

def confirm_verification_token(token, expiration=3600):
    """Confirms a verification token.

    Args:
        token (str): The token to confirm.
        expiration (int): The expiration time in seconds.

    Returns:
        str or bool: The email if valid, False otherwise.
    """
    try:
        email = s.loads(token, salt=app.config['SECRET_KEY'], max_age=expiration)
    except:
        return False
    return email

# Configure database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Load environment variables
load_dotenv()

# Mail configuration
app.config['MAIL_SERVER'] = 'swupelpms.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True  # Use SSL for secure communication
app.config['MAIL_USE_TLS'] = False 
app.config['MAIL_USERNAME'] = "info@swupelpms.com"  # Your email
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = "info@swupelpms.com"  # Default sender

mail = Mail(app)

# Store successes
SUCCESSES = {}

def send_verification_email(user_email):
    """Sends a verification email to the user.

    Args:
        user_email (str): The email address of the user.
    """
    token = generate_verification_token(user_email)
    verify_url = url_for('verify_email', token=token, _external=True)  # Generate verification URL
    
    # Create the email message
    msg = Message(
        'Confirm Your Email',  # Subject of the email
        recipients=[user_email],  # Recipient email
    )
    
    # HTML email content
    msg.html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; color: #e0e0e0; background-color: #192525;">
            <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #333; border-radius: 8px; background-color: #1e1e1e;">
                <h2 style="text-align: center; color: #5af0b9;">Welcome to Swupel!</h2>
                <p>Hello,</p>
                <p>Thank you for registering with us! Please confirm your email address to complete the signup process and start using our service.</p>
                <p style="text-align: center;">
                    <a href="{verify_url}" style="background-color: #5af0b9; color: #192525; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirm Email</a>
                </p>
                <p>If the button doesn't work, you can also confirm your email by clicking the following link:</p>
                <p><a href="{verify_url}" style="color: #5af0b9;">{verify_url}</a></p>
                <p>Best regards,<br>Swupel Team</p>
                <hr style="border: 0; border-top: 1px solid #333;">
                <p style="font-size: 12px; color: #888;">If you didn’t request this, please ignore this email.</p>
            </div>
        </body>
    </html>
    """
    
    # Send the email
    mail.send(msg)

class User(UserMixin, db.Model):
    """User model to represent registered users.

    Attributes:
        id (int): Primary DB key.
        username (str): Unique username of the user.
        email (str): Unique email of the user.
        password (str): Hashed password of the user.
        email_verified (bool): Status of email verification.
        primains (relationship): Relationship with Primain model.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    affiliated = db.Column(db.String(100), nullable=False)
    primains = relationship('Primain', backref='owner', lazy=True)
    
class Primain(db.Model):
    """Primain model to hold data of all registered Primains.

    Attributes:
        id (int): Primary DB key.
        primain_name (str): Custom unique name of the primain.
        address (str): Cryptographic address linked to the primain.
        chain (str): Chain on which the address is active.
        proof (str): Signature proving ownership over this primain.
        user_id (int): ID of the user who owns the primain.
    """
    id = db.Column(db.Integer, primary_key=True)
    primain_name = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    chain = db.Column(db.String(100), nullable=False)
    proof = db.Column(db.String(100), nullable=False)
    signature = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class Affiliate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    affiliate = db.Column(db.String(100), nullable=False)
    spent = db.Column(db.Integer, unique=False, nullable=False)
    payed_out = db.Column(db.Integer, unique=False, nullable=False)
    user_ids = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def send_password_reset_email(user_email):
    """Sends a password reset email to the user.

    Args:
        user_email (str): The email address of the user.
    """
    token = generate_verification_token(user_email)
    reset_url = url_for('reset_with_token', token=token, _external=True)

    msg = Message(
        'Reset Your Password',
        recipients=[user_email],
    )
    msg.html = f"""
    <html>
        <body>
            <p>To reset your password, click the following link:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
        </body>
    </html>
    """
    mail.send(msg)

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    """Resets the password using the token provided.

    Args:
        token (str): The token for password reset.

    Returns:
        html page: Renders the reset password template or redirects to login.
    """
    email = confirm_verification_token(token)
    if email is False:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password, method='scrypt')
            db.session.commit()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_with_token.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handles password reset request.

    Returns:
        html page: Renders the reset password template.
    """
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user.email)
            flash('A password reset email has been sent.', 'success')
        else:
            flash('Email address not found.', 'danger')
    return render_template('reset_password.html')

@login_manager.user_loader
def load_user(user_id):
    """Loads the database entry for the current user.

    Args:
        user_id (int): The ID of the current user.

    Returns:
        User: The User object.
    """
    return db.session.get(User, int(user_id))

def login_required(f):
    """Decorator function to ensure user is logged in.

    Args:
        f (function): The function to decorate.

    Returns:
        function: The decorated function.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/home')
@login_required
def index():
    """Displays the home page.

    Returns:
        html page: The index/home page.
    """
    return render_template('index.html')


@app.route('/add_primain<primain_n>',methods=['GET', 'POST'])
@login_required
def add_primain(primain_n):

    if request.method == 'POST':
        # Retrieve data from the form
        primain_name = request.form['primain_name']
        proof = request.form['proof']
        address = request.form['address']
        chain = request.form['chain_string']
        
        # Create signature
        signature = crypto_methods.serialize_signature_to_string(
            crypto_methods.sign_message(f"{primain_name}{address}{chain}{proof}".encode())
        )

        # Create new Primain object
        new_primain = Primain(
            primain_name=primain_name,
            address=json.dumps([address]),
            chain=json.dumps([chain]),
            proof=json.dumps([proof]),
            signature=json.dumps([signature]),
            user_id=current_user.id
        )
        message = f"{primain_name}{chain}{address}"
        
        SUCCESSES[current_user.id] = [new_primain, ""]
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        try:
            if chain == "Solana" :
                try:
                    signature_list=[int(x) for x in proof.split(",")]
                    proof=convert_signature_to_hex(signature_list)
                    
                    if not proof:
                        flash('Signature is invalid!', 'danger')
                        return redirect(url_for('register_primain'))
                    
                    valid = crypto_methods.verify_solana_signature(proof,message,address)
                except:
                    valid = crypto_methods.verify_solana_signature(proof,message,address)
            
            elif chain == "Bitcoin":
                
                if len(request.form['address']) == 34:
                    valid = crypto_methods.verify_bitcoin_signature(request.form['address'],request.form['proof'],message)
                else:
                    flash('Only Legacy Adress Format Accepted Currently!', 'danger')
                    return redirect(url_for('register_primain'))
                
            else:
                 valid = crypto_methods.verify_signature(proof, message, address)

            if valid:
                if not primain:
                    stripe.api_key = os.getenv('stripe_key')

                    session = stripe.checkout.Session.create(
                        line_items=[{
                            'price_data': {
                                'currency': 'eur',
                                'product_data': {
                                    'name': f'Purchase the {primain_name} Primain',
                                },
                                'unit_amount': 2000,
                            },
                            'quantity': 1,
                        }],
                        mode='payment',
                        success_url='http://localhost:5000/success',
                        cancel_url='http://localhost:5000/register_primain'
                    )

                    SUCCESSES[current_user.id] = [new_primain, session]
                    return redirect(session.url, code=303)
                else:
                    db.session.rollback()

                    if primain.user_id != current_user.id:
                        flash('You are not the Owner of this Primain!', 'danger')
                    elif proof in json.loads(primain.proof):
                        flash('You have already added this Address to your Primain!', 'danger')
                    else:
                        try:
                            # Update existing Primain with new data
                            new_address = json.loads(primain.address)
                            new_address.append(address)
                            primain.address = json.dumps(new_address)

                            new_chain = json.loads(primain.chain)
                            new_chain.append(chain)
                            primain.chain = json.dumps(new_chain)

                            new_proof = json.loads(primain.proof)
                            new_proof.append(proof)
                            primain.proof = json.dumps(new_proof)

                            new_signature = json.loads(primain.signature)
                            new_signature.append(signature)
                            primain.signature = json.dumps(new_signature)

                            # Commit changes to the database
                            db.session.commit()
                            flash('Primain registration successful!', 'success')
                            return redirect(url_for('view_owned_primains'))

                        except:
                            flash("An error occurred!", 'danger')
            else:
                flash('Data is invalid, check connected network!', 'danger')
        except:
            flash('Data is invalid!', 'danger')

    # If it's just a GET request, display the page
    return render_template('add_primain.html',primain_name=primain_n)


@app.route('/signup<affiliate>', methods=['GET', 'POST'])
def signup_affiliate(affiliate):
    """Handles user signup.

    Returns:
        html page: Renders the signup template.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
            
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, email=email, email_verified=False,affiliated=affiliate)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(email)
            
            flash('Signup successful! A verification email has been sent. Please verify your email.', 'success')
        
            try:
                aff=Affiliate.query.filter_by(affiliate=affiliate).first()
                user_ids=json.loads(aff.user_ids)
                user_ids.append(new_user.id)
                aff.user_ids=json.dumps(user_ids)
                db.session.commit()
            except Exception as e:
                print(e)
                new_refferal=Affiliate(affiliate=affiliate,spent=0,payed_out=0,user_ids=json.dumps([new_user.id]))
                db.session.add(new_refferal)
                db.session.commit()
                    
            return redirect(url_for('login'))
        except FileExistsError as e:
            db.session.rollback()
            flash('An error occurred during signup. Please try again.', 'danger')

    
    return render_template('signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user signup.

    Returns:
        html page: Renders the signup template.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, email=email, email_verified=False, affiliated="")

        try:
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(email)
            
            flash('Signup successful! A verification email has been sent. Please verify your email.', 'success')
        
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during signup. Please try again.', 'danger')
    
    return render_template('signup.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    """Verifies the user's email.

    Args:
        token (str): The verification token.

    Returns:
        html page: Redirects to login page after verification.
    """
    try:
        email = confirm_verification_token(token)
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first_or_404()
    if user.email_verified:
        flash('Account already verified. Please login.', 'success')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your account has been verified! You can now log in.', 'success')
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login.

    Returns:
        html page: Renders the login template.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if user.email_verified:
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Please verify your email before logging in.', 'danger')
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user.

    Returns:
        html page: Redirects to landing page.
    """
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect('/')  # Redirect to login page or home

@app.route('/success', methods=['GET'])
@login_required
def success():
    """Handles successful Primain registration.

    Returns:
        html page: Renders the index page after processing.
    """
    # Try adding the new Primain to the database
    if SUCCESSES.get(current_user.id):
        session_id = SUCCESSES[current_user.id][1].id
        
        checkout_session = stripe.checkout.Session.retrieve(
            session_id,
            expand=['line_items'],
        )
        
        if checkout_session.payment_status == "paid":
            db.session.add(SUCCESSES[current_user.id][0])
            db.session.commit()
        else:
            flash('Payment Failed!', 'danger')
    else:
        flash('Register Primain!', 'danger')
    
    checkout_session = stripe.checkout.Session.retrieve(
        session_id,
        expand=['line_items'],
    )
    
    del SUCCESSES[current_user.id]
    
    # Inform user of success
    flash('Primain registration successful!', 'success')
    try:
        aff=Affiliate.query.filter_by(affiliate=current_user.affiliated).first()
        if aff:
            aff.spent = aff.spent+20
            db.session.commit()
    except:
        pass
        
    return redirect(url_for("index"))

def convert_signature_to_hex(signature_ints):
    """Convert a list of integers (signature) to a hexadecimal string.

    Args:
        signature_ints (list): A list of 64 integers (0-255).

    Returns:
        str: Hexadecimal representation of the signature, or None if invalid.
    """
    # Check if the input is a list of 64 integers
    if isinstance(signature_ints, list) and len(signature_ints) == 64:
        if all(isinstance(i, int) and 0 <= i <= 255 for i in signature_ints):
            # Convert to bytes
            signature_bytes = bytes(signature_ints)
            # Convert to hexadecimal
            return signature_bytes.hex()
    return None  # Return None if invalid format

@app.route('/register_primain', methods=['GET', 'POST'])
@login_required
def register_primain():
    """Registers a new Primain to the database.

    Returns:
        html page: Either home or register_primain.
    """
    if request.method == 'POST':
        # Retrieve data from the form
        primain_name = request.form['primain_name'].lower()
        proof = request.form['proof']
        address = request.form['address']
        chain = request.form['chain_string']
        
        # Create signature
        signature = crypto_methods.serialize_signature_to_string(
            crypto_methods.sign_message(f"{primain_name}{address}{chain}{proof}".encode())
        )

        # Create new Primain object
        new_primain = Primain(
            primain_name=primain_name,
            address=json.dumps([address]),
            chain=json.dumps([chain]),
            proof=json.dumps([proof]),
            signature=json.dumps([signature]),
            user_id=current_user.id
        )
        message = f"{primain_name}{chain}{address}"
        
        SUCCESSES[current_user.id] = [new_primain, ""]
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        try:
            if chain == "Solana" :
                try:
                    signature_list=[int(x) for x in proof.split(",")]
                    proof=convert_signature_to_hex(signature_list)
                    
                    if not proof:
                        flash('Signature is invalid!', 'danger')
                        return redirect(url_for('register_primain'))
                    
                    valid = crypto_methods.verify_solana_signature(proof,message,address)
                except:
                    valid = crypto_methods.verify_solana_signature(proof,message,address)
            
            elif chain == "Bitcoin":
                
                if len(request.form['address']) == 34:
                    valid = crypto_methods.verify_bitcoin_signature(request.form['address'],request.form['proof'],message)
                else:
                    flash('Only Legacy Adress Format Accepted Currently!', 'danger')
                    return redirect(url_for('register_primain'))
                
            else:
                 valid = crypto_methods.verify_signature(proof, message, address)

            if valid:
                if not primain:
                    stripe.api_key = os.getenv('stripe_key')

                    session = stripe.checkout.Session.create(
                        line_items=[{
                            'price_data': {
                                'currency': 'eur',
                                'product_data': {
                                    'name': f'Purchase the {primain_name} Primain',
                                },
                                'unit_amount': 2000,
                            },
                            'quantity': 1,
                        }],
                        mode='payment',
                        success_url='http://localhost:5000/success',
                        cancel_url='http://localhost:5000/register_primain'
                    )

                    SUCCESSES[current_user.id] = [new_primain, session]
                    return redirect(session.url, code=303)
                else:
                    db.session.rollback()

                    if primain.user_id != current_user.id:
                        flash('You are not the Owner of this Primain!', 'danger')
                    elif proof in json.loads(primain.proof):
                        flash('You have already added this Address to your Primain!', 'danger')
                    else:
                        try:
                            # Update existing Primain with new data
                            new_address = json.loads(primain.address)
                            new_address.append(address)
                            primain.address = json.dumps(new_address)

                            new_chain = json.loads(primain.chain)
                            new_chain.append(chain)
                            primain.chain = json.dumps(new_chain)

                            new_proof = json.loads(primain.proof)
                            new_proof.append(proof)
                            primain.proof = json.dumps(new_proof)

                            new_signature = json.loads(primain.signature)
                            new_signature.append(signature)
                            primain.signature = json.dumps(new_signature)

                            # Commit changes to the database
                            db.session.commit()
                            flash('Primain registration successful!', 'success')
                            return redirect(url_for('index'))

                        except:
                            flash("An error occurred!", 'danger')
            else:
                flash('Data is invalid, check connected network!', 'danger')
        except:
            flash('Data is invalid!', 'danger')

    # If it's just a GET request, display the page
    return render_template('register_primain.html')

@app.route('/check_primain_availability')
def check_primain_availability():
    """Check if the Primain name is available."""
    primain_name = request.args.get('primain_name').lower()

    if primain_name:
        # Check if the Primain already exists in the database
        primain = Primain.query.filter_by(primain_name=primain_name).first()

        if primain:
            return jsonify({'available': False})  # Not available
        else:
            return jsonify({'available': True})  # Available
    else:
        return jsonify({'available': False})  # Invalid input
    
@app.route('/check_username_availability')
def check_username_availability():
    """Check if the Primain name is available."""
    username = request.args.get('username')
    print(username)
    if username:
        # Check if the Primain already exists in the database
        user = User.query.filter_by(username=username).first()

        if user:
            return jsonify({'available': False})  # Not available
        else:
            return jsonify({'available': True})  # Available
    else:
        print("invalid")
        return jsonify({'available': False})  # Invalid input

@app.route('/delete_adress<primain_name>', methods=['DELETE', 'GET'])
@login_required
def delete_address(primain_name):
    """Display the address of the inputted Primain name.

    Args:
        primain_name (str): Name of the Primain for which to find the address.

    Returns:
        html page: Html page filled with either address data or an error.
    """
    # Query the database to find the Primain with the given name
    if request.method == 'GET':
        
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        
        if primain:
            # Render the template with the address and the Primain name
            return render_template('delete_adresses.html', 
                                address=json.loads(primain.address), 
                                primain_name=primain_name,
                                network=json.loads(primain.chain), 
                                error=None)
        else:
            # Render the template with an error message
            return render_template('delete_adresses.html', 
                                address=None, 
                                primain_name=primain_name, 
                                network=None, 
                                error='No Addresses linked to this Primain')
    else:
        try:
            data = request.get_json()
            primain_name = data.get('primain_name')
            address_to_delete = data.get('address')
            chain_to_delete = data.get('chain')
            
            # Fetch the Primain for the current user
            primain = Primain.query.filter_by(primain_name=primain_name, user_id=current_user.id).first()

            if not primain:
                return jsonify({'error': 'Primain not found or you do not have permission to delete this address.'}), 404
            
            # Load existing addresses, chains, proofs, and signatures
            existing_addresses = json.loads(primain.address)
            existing_chains = json.loads(primain.chain)
            existing_proofs = json.loads(primain.proof)
            existing_signatures = json.loads(primain.signature)

            # Check if the address and chain combination to delete exists in the Primain
            if address_to_delete not in existing_addresses or chain_to_delete not in existing_chains:
                return jsonify({'error': 'Address or Chain not found in this Primain.'}), 404

            # Get the index of the address and chain to delete
            index_to_delete = None
            for i in range(len(existing_addresses)):
                if existing_addresses[i] == address_to_delete and existing_chains[i] == chain_to_delete:
                    index_to_delete = i
                    break

            if index_to_delete is None:
                return jsonify({'error': 'No matching address and chain combination found.'}), 404

            # Remove the corresponding address, chain, proof, and signature
            del existing_addresses[index_to_delete]
            del existing_chains[index_to_delete]
            del existing_proofs[index_to_delete]
            del existing_signatures[index_to_delete]

            # Update the Primain with the new data
            primain.address = json.dumps(existing_addresses)
            primain.chain = json.dumps(existing_chains)
            primain.proof = json.dumps(existing_proofs)
            primain.signature = json.dumps(existing_signatures)

            # Commit the changes to the database
            db.session.commit()

            return jsonify({'message': 'Address and chain deleted successfully'}), 200

        except Exception as e:
            db.session.rollback()  # Roll back any changes in case of error
            return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/<primain_name>')
def display_address(primain_name):
    """Display the address of the inputted Primain name.

    Args:
        primain_name (str): Name of the Primain for which to find the address.

    Returns:
        html page: Html page filled with either address data or an error.
    """
    # Query the database to find the Primain with the given name
    primain = Primain.query.filter_by(primain_name=primain_name.lower()).first()
    
    if primain:
        data = (
            f"Primain name: {primain_name}\n"
            f"Primain Addresses: {primain.address}\n"
            f"Blockchain Networks: {primain.chain}\n"
            f"User Proofs: {primain.proof}\n"
            f"Backend Signatures: {primain.signature}\n"
            f"Public Key: {crypto_methods.serialize_public_key_to_string(crypto_methods.load_keys()[1])}\n"
            f"Structure of signed string that was signed: primain_name + primain.address + primain.chain + primain.proof"
        )
        # Render the template with the address and the Primain name
        return render_template('display_address.html', 
                               address=json.loads(primain.address), 
                               primain_name=primain_name,
                               network=json.loads(primain.chain), 
                               data=data, 
                               error=None)
    else:
        # Render the template with an error message
        return render_template('display_address.html', 
                               address=None, 
                               primain_name=primain_name, 
                               network=None, 
                               error='No Addresses linked to this Primain')


@app.route('/', methods=['POST', 'GET'])
def get_address():
    """Handles address retrieval based on Primain name.

    Returns:
        json: Redirect URL or error message.
    """
    if request.method == 'POST':
        primain_name = request.form['primain_name']
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        if primain:
            return jsonify({'redirect': url_for('display_address', primain_name=primain_name)})
        else:
            return jsonify({'error': 'No Primain With This Name was Found!'})

    return render_template('get_address.html')


@app.route('/view_owned_primains')
@login_required
def view_owned_primains():
    """Returns html page with all owned Primains.

    Returns:
        html page: Page filled with owned Primains or an error.
    """
    # If user owns Primains, display them
    if current_user.primains:
        return render_template('view_owned_primains.html', primains=current_user.primains)
    else:
        # Otherwise show error
        flash('No Primains found for this user.', 'info')
        return render_template('view_owned_primains.html')

@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    new_username = request.form['username']
    password = request.form['password']
    
    user = current_user
    if check_password_hash(user.password, password):
        user.username=new_username
        try:
            db.session.commit()
            flash('Updated username!', 'success')
            return redirect(url_for('manage_account'))
        except:
            db.session.rollback()
            flash('Username is already taken!', 'danger')
            return redirect(url_for('manage_account'))

    return redirect(url_for('manage_account'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    user = current_user
    if check_password_hash(user.password, current_password):
        user.password = generate_password_hash(new_password, method='scrypt')
        db.session.commit()
        flash('Your password has been updated!', 'success')

    return redirect(url_for('manage_account'))

@app.route('/manage_account')
@login_required
def manage_account():
    user_name = current_user.username
    return render_template('manage_account.html', user_name=user_name)

@app.route('/generate_affiliate_link')
@login_required
def generate_affiliate_link():
    user_id = current_user.id
    affiliate_link = f"https://swupelpms.org/affiliate/{user_id}"
    return affiliate_link  # Logic to generate an affiliate link for the user

@app.route('/TOS')
@login_required
def terms_of_service():
    return render_template("TOS.html")

@app.route('/contact')
@login_required
def contact():
    return render_template("contact.html")

# Run file if executed directly
if __name__ == '__main__':
    # Create/Load database and then run app
    with app.app_context():
        db.create_all()
    app.run(debug=True)
