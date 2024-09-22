#Manage partial imports
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_required, current_user,login_user,LoginManager,UserMixin,logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from dotenv import load_dotenv
from flask_mail import Mail, Message


#Manage full imports
import crypto_methods
import json
import stripe
import os

#Configure flask app
app = Flask("Swupel Primain Service")
app.config['SECRET_KEY'] = crypto_methods.PASSWORD
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Generate a serializer object with the app's secret key
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_verification_token(email):
    return s.dumps(email, salt=app.config['SECRET_KEY'])

def confirm_verification_token(token, expiration=3600):
    try:
        email = s.loads(token, salt=app.config['SECRET_KEY'], max_age=expiration)
    except:
        return False
    return email

#Configure database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

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

SUCCESSES={}

# Generate a serializer object with the app's secret key
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_verification_token(email):
    return s.dumps(email, salt=app.config['SECRET_KEY'])

def confirm_verification_token(token, expiration=3600):
    try:
        email = s.loads(token, salt=app.config['SECRET_KEY'], max_age=expiration)
    except:
        return False
    return email

def send_verification_email(user_email):
    
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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add email field
    password = db.Column(db.String(100), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)  # Email verification status
    primains = relationship('Primain', backref='owner', lazy=True)


class Primain(db.Model):
    """Primain class used to hold data of all registered Primains

    Args:
        db (Class): Current database model
        
    Attributes:
        id: Primary DB key
        primain_name: Costum unique name of the primain (is also what gets displayed)
        address: Cryptographic address linked to the primain
        chain: Chain on which the address is active
        proof: Signature which proofs ownership over this primain
        user_id: Id of the user which owns the primain
    """
    id = db.Column(db.Integer, primary_key=True)
    primain_name = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    chain =  db.Column(db.String(100), nullable=False)
    proof = db.Column(db.String(100), nullable=False)
    signature = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def send_password_reset_email(user_email):
    token = generate_verification_token(user_email)  # Reuse the existing token generation
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

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
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
    """Loads the database entry for the current user

    Args:
        user_id (int): The ID of the current user

    Returns:
        User: User object
    """
    return db.session.get(User, int(user_id))

def login_required(f):
    """Decorator function to decorate all routings where login is mandatory

    Args:
        f (function): function which is decorated with this method

    Returns:
        function: The decorator function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        
        #If the user is not authenticated log out the user
        if not current_user.is_authenticated:
            flash('You need to be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/home')
@login_required
def index():
    """Displays the home page

    Returns:
        html page: The index/home page
    """
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # Add email input field in the form
        
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, email=email, email_verified=False)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(email)
            
            flash('Signup successful! A verification email has been sent. Please verify your email.', 'success')
            return redirect(url_for('login'))
        except FileExistsError:
            db.session.rollback()
            flash('An error occurred during signup. Please try again.', 'danger')
    
    return render_template('signup.html')

@app.route('/verify_email/<token>')
def verify_email(token):
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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if user.email_verified:
                login_user(user)
                flash('Login successful!', 'success')
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
        html page: Redirects to landing page
    """
    
    # Use Flask-Login's logout_user function to log out
    logout_user()
    flash('You have been logged out.', 'info')
    
    return redirect('/') # Redirect to login page or home

@app.route('/success', methods=['GET'])
@login_required
def sucess():
    #try adding the new Primain to the database
    if SUCCESSES[current_user.id]:
        session_id=SUCCESSES[current_user.id][1].id
        
        checkout_session = stripe.checkout.Session.retrieve(
        session_id,
        expand=['line_items'],
        )
        
        if checkout_session.payment_status == "paid":
            db.session.add(SUCCESSES[current_user.id][0])
            db.session.commit()
        else:
            flash('Pyment Failed!', 'danger')
    else:
        flash('Register Primain!', 'danger')
    
    checkout_session = stripe.checkout.Session.retrieve(
    session_id,
    expand=['line_items'],
    )
    
    
    del SUCCESSES[current_user.id]
    #inform user of success
    flash('Primain registration successful!', 'success')
    return render_template("index.html")


@app.route('/register_primain', methods=['GET', 'POST'])
@login_required
def register_primain():
    """Registers a new primain to the database

    Returns:
        html page: Either home or register_primain
    """
    
    #If user has submitted the form
    if request.method == 'POST':
        
        #Retrive data from the form
        primain_name = request.form['primain_name']
        proof = request.form['proof']
        address = request.form['address']
        chain = request.form['chain_string']
          
        
        #Create signature
        signature=crypto_methods.serialize_signature_to_string(crypto_methods.sign_message(f"{primain_name}{address}{chain}{proof}".encode()))

        #create new primain object and build message string 
        new_primain = Primain(primain_name=primain_name, address=json.dumps([address]), chain=json.dumps([chain]),proof=json.dumps([proof]),signature=json.dumps([signature]), user_id=current_user.id)
        message = f"{primain_name}{chain}{address}"
        
        SUCCESSES[current_user.id]=[new_primain,""]
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        try:
            
            #verify if user actually owns the address
            valid = crypto_methods.verify_signature(proof, message, address)
            
            #if thats the case
            if valid:
                
                if not primain:
                    #check if user has exceeded max amount of primains
                    if len(current_user.primains) >= 3:
                        
                        #inform user if that is the case
                        flash('You can only own a maximum of 3 primains.', 'danger')
                        return redirect(url_for('register_primain'))

                    
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
                    success_url=f'http://localhost:5000/success',
                    cancel_url='http://localhost:5000/register_primain')

                    SUCCESSES[current_user.id]=[new_primain,session]
                    return redirect(session.url, code=303)
            
                else:

                    db.session.rollback()
                    
                    if primain.user_id != current_user.id:
                        flash('You are not the Owner of this Primain!', 'danger')
                    elif proof in json.loads(primain.proof):
                        flash('You have already added this Address to your Primain!', 'danger')
                    else:
                        
                        try:

                            new_address=json.loads(primain.address)
                            new_address.append(address)
                            primain.address=json.dumps(new_address)
                            
                            new_chain=json.loads(primain.chain)
                            new_chain.append(chain)
                            primain.chain=json.dumps(new_chain)
                            
                            new_proof=json.loads(primain.proof)
                            new_proof.append(proof)
                            primain.proof=json.dumps(new_proof)
                            
                            new_signature=json.loads(primain.signature)
                            new_signature.append(signature)
                            primain.signature=json.dumps(new_signature)
                            
                            #try adding the new Primain to the database
                            db.session.commit()
                            #inform user of success
                            flash('Primain registration successful!', 'success')
                            return redirect(url_for('index'))

                        except:
                            flash("An error occured!", 'danger')
                    
            else:
                flash('Data is invalid, Check connected Network!', 'danger')
        except:
            flash('Data is invalid!', 'danger')
    
    #if its just a get request just display the page
    return render_template('register_primain.html')

@app.route('/<primain_name>')
def display_address(primain_name):
    """Display the address of the inputted primain name

    Args:
        primain_name (string): Name of the primain for which to find the address

    Returns:
        html page: Html page filled with either address data or an error
    """
    # Query the database to find the primain with the given name
    primain = Primain.query.filter_by(primain_name=primain_name).first()
    
    #if found
    if primain:
        
        data=f"Primain name: {primain_name}\nPrimain Addresses: {primain.address}\nBlockchain Networks: {primain.chain}\nUser Proofs: {primain.proof} \nBackend Signatures: {primain.signature} \nPublic Key: {crypto_methods.serialize_public_key_to_string(crypto_methods.load_keys()[1])}\nStructure of signed string that was signed: primain_name+primain.address+primain.chain+primain.proof"
        # Render the template with the address and the primain name
        return render_template('display_address.html', address=json.loads(primain.address), primain_name=primain_name,network=json.loads(primain.chain), data=data, error=None)
    
    else:
        # Render the template with an error message
        return render_template('display_address.html', address=None, primain_name=primain_name, network=None, error='No Addresses linked to this Primain')

@app.route('/', methods=['POST', 'GET'])
def get_address():
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
    """Returns html page with all owned primains

    Returns:
        html page: page filled with owned primains or an error
    """

    #If user owns primains display them
    if current_user.primains:
        return render_template('view_owned_primains.html', primains=current_user.primains)
    
    #otherwise show error
    else:
        flash('No Primains found for this user.', 'info')
        return render_template('view_owned_primains.html')
    
#Run file if executed directly
if __name__ == '__main__':
    
    #Create/Load database and then run app
    with app.app_context():
        db.create_all()
    app.run(debug=True)
