#Manage partial imports
from flask_login import login_required, current_user, login_user, LoginManager, UserMixin, logout_user
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from dotenv import load_dotenv
from functools import wraps

#Manage full imports
import crypto_methods
import json
import stripe
import os

#Configure Flask app
app = Flask("Swupel Primain Service")
app.config['SECRET_KEY'] = crypto_methods.PASSWORD
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

#Generate a serializer object with the app's secret key
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#Configure database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

#Load environment variables
load_dotenv()

#Mail configuration
app.config['MAIL_SERVER'] = 'swupelpms.com' #Mail server domain
app.config['MAIL_PORT'] = 465 #Port to send from
app.config['MAIL_USE_SSL'] = True  # Use SSL for secure communication
app.config['MAIL_USE_TLS'] = False #Dont use TLS
app.config['MAIL_USERNAME'] = "email.verification@swupelpms.com"  #Your email
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')  #Your email password
app.config['MAIL_DEFAULT_SENDER'] = "email.verification@swupelpms.com"  #Default sender
mail = Mail(app)

#Store successes
SUCCESSES = {}

#Store prices
PRICE_IDS=[
    'price_1QcngaKot5J3VBeNVPrjyYhl',
    'price_1Qcng1Kot5J3VBeNt6IxtnGh',
    'price_1QcnfQKot5J3VBeNXuw9qxKw',
    'price_1QcnepKot5J3VBeN73unZz0s',
    'price_1QcndtKot5J3VBeNjoXAGi2j',
    'price_1QcncwKot5J3VBeNXH5Qy5A8',
    'price_1QcncJKot5J3VBeNqZDF6ne3'
]
PRICES= [999.0, 550.0, 250.0, 99.0, 50.0, 20.0, 10.0]


class User(UserMixin, db.Model):
    """User model to represent registered users.

    Attributes:
        id (int): Primary DB key.
        username (str): Unique username of the user.
        email (str): Unique email of the user.
        password (str): Hashed password of the user.
        email_verified (bool): Status of email verification.
        affiliated (str): Affiliate organization or association for the user.
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
        signature (str): Signature for verification, linked to ownership proof.
        user_id (int): ID of the user who owns the primain.
        subscription_id (str): Stripe subscription ID  
    """
    id = db.Column(db.Integer, primary_key=True)
    primain_name = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    chain = db.Column(db.String(100), nullable=False)
    proof = db.Column(db.String(100), nullable=False)
    signature = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscription_id = db.Column(db.String(100), nullable=False)
    
class Affiliate(db.Model):
    """Affiliate model to track user affiliations and payment details.

    Attributes:
        id (int): Primary DB key.
        affiliate (str): Name or identifier of the affiliate organization.
        spent (int): Total amount spent by the user within the affiliate program.
        payed_out (int): Total amount paid out to the user from the affiliate program.
        user_ids (int): Foreign key linking the affiliate record to a user.
    """
    id = db.Column(db.Integer, primary_key=True)
    affiliate = db.Column(db.String(100), nullable=False)
    spent = db.Column(db.Integer, unique=False, nullable=False)
    payed_out = db.Column(db.Integer, unique=False, nullable=False)
    user_ids = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


def generate_verification_token(email):
    """Generates a verification token for a given email.

    Args:
        email (str): The email address to generate a token for.

    Returns:
        str: The generated token.
    """
    return s.dumps(email, salt=app.config['SECRET_KEY'])


@app.route('/cancel_subscription/<primain_name>', methods=['POST'])
def cancel_subscription(primain_name):
    """Function which allows users to cancel their subscription

    Args:
        primain_name (str): Name of the Primain which they want to cancel their subscription for

    Returns:
        Json: Confirmation Message
    """
    try:

        #Retrieve primain from DB
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        
        #If it cant be found return an error
        if not primain:
            return jsonify({"message": "Error canceling subscription!"}), 400
        
        #Inform user if they dont own the Primain
        if primain.user_id != current_user.id:
            return jsonify({"message": "You are not the owner of this Primain"}), 400
        
        #Cancel the stripe subscription via the id stored in the primain
        stripe.api_key = os.getenv('stripe_key')        
        subscription = stripe.Subscription.retrieve(primain.subscription_id)
        subscription.cancel()
        
        #Commit deletion of the primain to the DB
        db.session.delete(primain)
        db.session.commit()

        #Return confirmation
        return jsonify({"message": "Subscription canceled successfully"})
    
    #Catch and return any error
    except Exception as e:
        return jsonify({"message": "Error canceling subscription: " + str(e)}), 400


def check_subscription_status(subscription_id):
    """Checks status of a users subscription

    Args:
        subscription_id (str): Stripe subscription ID

    Returns:
        bool: Validity of the id
    """
    try:
        
        #Set API key
        stripe.api_key = os.getenv('stripe_key')            
        
        #Retrieve the subscription using the subscription ID
        subscription = stripe.Subscription.retrieve(subscription_id)
        
        #Check the status of the subscription
        if subscription['status'] == 'active':
            return True
        
        #Subscription is past due, meaning payment failed but it might still be valid
        elif subscription['status'] == 'past_due':
            return True
        
        #Subscription is not valid anymore
        else:
            return False
        
    #Catch any errors
    except Exception as e:
        return False


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


def send_verification_email(user_email):
    """Sends a verification email to the user.

    Args:
        user_email (str): The email address of the user.
    """
    
    #Generate token and url for email
    token = generate_verification_token(user_email)
    verify_url = url_for('verify_email', token=token, _external=True)  #Generate verification URL
    
    #Create the email message
    msg = Message(
        'Confirm Your Email',  #Subject of the email
        recipients=[user_email],  #Recipient email
    )
    
    #HTML email content
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
    
    #Send the email
    mail.send(msg)


def send_password_reset_email(user_email):
    """Sends a password reset email to the user.

    Args:
        user_email (str): The email address of the user.
    """
    
    #Generate token and url for email
    token = generate_verification_token(user_email)
    reset_url = url_for('reset_with_token', token=token, _external=True)

    #Create the email message
    msg = Message(
        'Reset Your Password', #Subject
        recipients=[user_email], #Recipient
    )
    
    #Email content
    msg.html = f"""
    <html>
        <body>
            <p>To reset your password, click the following link:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
        </body>
    </html>
    """
    
    #Send the email
    mail.send(msg)
    
    
def login_required(f):
    """Decorator function to ensure user is logged in.

    Args:
        f (function): The function to decorate.

    Returns:
        function: The decorated function.
    """
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        
        #If user is not logged in a warning will be displayed
        if not current_user.is_authenticated:
            flash('You need to be logged in to view this page.', 'warning')
            
            #And the user will be redirected
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    
    return decorated_function


#----From this point on only server routes----


@app.route('/about', methods=['GET'])
def about():
    """Returns the FAQs

    Returns:
        html page: The FAQs page
    """
    
    return render_template('about.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    """Resets the password using the token provided.

    Args:
        token (str): The token for password reset.

    Returns:
        html page: Renders the reset password template or redirects to login.
    """
    
    #Verify token and display error if invalid
    email = confirm_verification_token(token)
    if email is False:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    #If POST request
    if request.method == 'POST':
        
        #Get new password
        password = request.form['password']
        
        #Verify its security according to NIST2024 security guidelines
        if len(password) <= 12:
            flash('Password must be atleast 12 characters long!', 'danger')
            return render_template('reset_with_token.html')
            
        #Seach for user
        user = User.query.filter_by(email=email).first()
        if user:
            
            #Update the password of the new user and store it securely
            user.password = generate_password_hash(password, method='scrypt')
            db.session.commit()
            
            #Inform and redirect user
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))

    #Return page upon get request
    return render_template('reset_with_token.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handles password reset request.

    Returns:
        html page: Renders the reset password template.
    """
    
    #If a post request is sent
    if request.method == 'POST':
        
        #Search user by inputted email
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        #If user exists send reset email.. otherwise display error
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
    
    #return user object by ID
    return db.session.get(User, int(user_id))


@app.route('/home')
@login_required
def index():
    """Displays the home page.

    Returns:
        html page: The index/home page.
    """
    
    return render_template('index.html')


@app.route('/register_primain/', defaults={'primain_n': None}, methods=['GET', 'POST'])
@app.route('/register_primain/<primain_n>', methods=['GET', 'POST'])
@login_required
def register_primain(primain_n):
    """Enables users to buy their own Primain

    Args:
        primain_n (str): Primain name (n) 

    Returns:
        html page: Either a payment page or an error message
    """
    
    #If data is submitted
    if request.method == 'POST':
        
        #Retrieve data from the form
        primain_name = request.form['primain_name']
        
        #If name is too long inform and redirect
        if len(primain_name) >= 50:
            flash('Only Names under 50 Characters Permitted!', 'danger')
            return redirect(url_for("index"))
        
        #Retrieve remaining data
        proof = request.form['proof']
        address = request.form['address']
        chain = request.form['chain_string']

        #If user just entered the desired name
        if proof == "" or address == "" or chain == "":
            return redirect(url_for("register_primain_without_address",primain_name=primain_name))
        
        #Create signature
        signature = crypto_methods.serialize_signature_to_string(
            crypto_methods.sign_message(f"{primain_name}{address}{chain}{proof}".encode())
        )

        #Create new Primain object
        new_primain = Primain(
            primain_name=primain_name,
            address=json.dumps([address]),
            chain=json.dumps([chain]),
            proof=json.dumps([proof]),
            signature=json.dumps([signature]),
            user_id=current_user.id,
            subscription_id=""
        )
        
        #Create message to verify frontend signature
        message = f"{primain_name}{chain}{address}"
        
        #Initialize Payment success entry for this user
        SUCCESSES[current_user.id] = [new_primain, ""]
        
        #Retrieve primain under the same name if available
        primain = Primain.query.filter_by(primain_name=primain_name).first()
                
        #If Primain object exists
        if primain:
            
            #And subscription has expired
            if not check_subscription_status(primain.subscription_id):
                
                #Delete the primain so other users can buy it
                db.session.delete(primain)
                db.session.commit()
                primain = None
        
        try:
            #Specific logic for Solana signatures
            if chain == "Solana":
                
                try:
                    #If Signature is not already in hex string format, convert it
                    signature_list = [int(x) for x in proof.split(",")]
                    proof = convert_signature_to_hex(signature_list)
                    
                    #If conversion fails, throw error
                    if not proof:
                        flash('Signature is invalid!', 'danger')
                        return redirect(url_for("index"))
                    
                    #Otherwise determine validity
                    
                    valid = crypto_methods.verify_solana_signature(proof, message, address)
                except:
                    
                    #If signature was already in hex format, an error will trigger the except
                    valid = crypto_methods.verify_solana_signature(proof, message, address)

            #Specific logic for Bitcoin signatures
            elif chain == "Bitcoin":
                
                #If BTC address is 34 chars long
                if len(request.form['address']) == 34:
                    # Determine signature validity
                    valid = crypto_methods.verify_bitcoin_signature(request.form['address'], request.form['proof'], message)
                
                else:
                    flash('Only Legacy Address Format Accepted Currently!', 'danger')
                    return redirect(url_for("index"))
            else:
                
                #Verify using standard signature verification for other chains
                valid = crypto_methods.verify_signature(proof, message, address)

            #If the signature is valid (proving user actually owns the wallet)
            if valid:
                
                #If the Primain isn't registered yet
                if not primain:
                
                    #Get the Stripe API key and create a checkout session for subscription
                    stripe.api_key = os.getenv('stripe_key')
                    
                    #Use the price ID for the yearly subscription (choose dynamically depending on len of the Primain)
                    if len(primain_name)-1 <= len(PRICE_IDS):
                        subscription_price_id = PRICE_IDS[len(primain_name)-1]
                        
                    #If primain is longer than list take 7+ option
                    else:
                        subscription_price_id = PRICE_IDS[-1]
                    
                    #Create the session
                    session = stripe.checkout.Session.create(
                        payment_method_types=['card'],
                        line_items=[{
                            'price': subscription_price_id, 
                            'quantity': 1,
                        }],
                        mode='subscription',  
                        success_url=request.url_root+'success',  
                        cancel_url=request.url_root+'home',
                    )

                    #Update user's successes with the session so it can be verified
                    SUCCESSES[current_user.id] = [new_primain, session]
                    
                    #Redirect to the Db logic
                    return redirect(session.url, code=303)
                else:
                    
                    #Reverse any uncommitted changes to the DB
                    db.session.rollback()

                    #If user doesn't own the Primain
                    if primain.user_id != current_user.id:
                        flash('You are not the Owner of this Primain!', 'danger')
                    
                    #If user tries to add an address they already added
                    elif proof in json.loads(primain.proof):
                        flash('You have already added this Address to your Primain!', 'danger')
                    
                    else:
                        try:
                            
                            #Update existing Primain with new address 
                            new_address = json.loads(primain.address)
                            new_address.append(address)
                            primain.address = json.dumps(new_address)

                            #Update existing Primain with new network
                            new_chain = json.loads(primain.chain)
                            new_chain.append(chain)
                            primain.chain = json.dumps(new_chain)

                            #Update existing Primain with new proof
                            new_proof = json.loads(primain.proof)
                            new_proof.append(proof)
                            primain.proof = json.dumps(new_proof)

                            #Update existing Primain with new signature 
                            new_signature = json.loads(primain.signature)
                            new_signature.append(signature)
                            primain.signature = json.dumps(new_signature)

                            #Commit changes to the database and inform user
                            db.session.commit()
                            flash('Primain registration successful!', 'success')
                            
                            #Redirect to the owned primains
                            return redirect(url_for('view_owned_primains'))
                        
                        except:
                            
                            flash("An error occurred!", 'danger')
            else:
                flash('Data is invalid, check connected network!', 'danger')
        except:
            flash('Data is invalid!', 'danger')

    #If it's just a GET request, display the page, either registering or adding page
    if primain_n != None:
        return render_template('add_primain.html', primain_name=primain_n)
    else:
        return render_template('register_primain.html')


@app.route('/register_primain_without_address/<primain_name>', methods=['GET'])
@login_required
def register_primain_without_address(primain_name):
    """Enables users to buy their own Primain even without a wallet

    Args:
        primain_n (str): Primain name (n) 

    Returns:
        html page: Either a payment page or an error message
    """

    #Create new Primain object
    new_primain = Primain(
        primain_name=primain_name,
        address=json.dumps([]),
        chain=json.dumps([]),
        proof=json.dumps([]),
        signature=json.dumps([]),
        user_id=current_user.id,
        subscription_id=""
    )
    
    #Initialize Payment success entry for this user
    SUCCESSES[current_user.id] = [new_primain, ""]
    
    #Retrieve primain under the same name if available
    primain = Primain.query.filter_by(primain_name=primain_name).first()
    
    #If Primain object exists
    if primain:
        
        #And subscription has expired
        if not check_subscription_status(primain.subscription_id):
            
            #Delete the primain so other users can buy it
            db.session.delete(primain)
            db.session.commit()
            primain = None
    
    try:
        
        #If the Primain isn't registered yet
        if not primain:
        
            #Get the Stripe API key and create a checkout session for subscription
            stripe.api_key = os.getenv('stripe_key')
            
            #Use the price ID for the yearly subscription (choose dynamically depending on len of the Primain)
            if len(primain_name)-1 < len(PRICE_IDS):
                subscription_price_id = PRICE_IDS[len(primain_name)-1]
                
            #If primain is longer than list take 7+ option
            else:
                subscription_price_id = PRICE_IDS[-1]
            
            #Create the session
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': subscription_price_id, 
                    'quantity': 1,
                }],
                mode='subscription',  
                success_url=request.url_root+'success',  
                cancel_url=request.url_root+'home',
            )

            #Update user's successes with the session so it can be verified
            SUCCESSES[current_user.id] = [new_primain, session]
            
            #Redirect to the Db logic
            return redirect(session.url, code=303)
        else:
            
            #Reverse any uncommitted changes to the DB
            db.session.rollback()

            #If user doesn't own the Primain
            if primain.user_id != current_user.id:
                flash('You are not the Owner of this Primain!', 'danger')
            else:
                flash("Add new Addresses to your Primain by clicking the + in owned Primains!",'danger') 
                
    except:
        flash("An error occured!","danger")
        
    #Redirect to home page
    return redirect(url_for("index"))


@app.route('/success', methods=['GET'])
@login_required
def success():
    """Manages the Primain registration logic after a successful payment

    Returns:
        html page: Redirects user to the home page
    """
    #Set API key
    stripe.api_key = os.getenv('stripe_key')                 
    
    #Retrive the current users Success (Primain object)
    if SUCCESSES.get(current_user.id):
        
        #Get the user's checkout session ID
        session_id = SUCCESSES[current_user.id][1].id
        
        #Retrieve the checkout session
        checkout_session = stripe.checkout.Session.retrieve(
            session_id,
            expand=['line_items'],
        )
        
        #If the payment was successful (subscription payment)
        if checkout_session.payment_status == "paid":
            
            #Get the newly bought Primain and modify the subscription id to reflect the actual id
            new_primain=SUCCESSES[current_user.id][0]
            new_primain.subscription_id = checkout_session.subscription
                        
            #Add the Primain to DB as the payment was successful
            db.session.add(new_primain)
            db.session.commit()

    #Inform the user of any failures
        else:
            flash('Payment Failed!', 'danger')
    else:
        flash('Register Primain!', 'danger')
    
    try:
        #Delete payment success (reset for next purchase)
        del SUCCESSES[current_user.id]
    except:
        pass
        
    #Inform user of success
    flash('Primain registration successful!', 'success')
    
    #Handle affiliate logic if applicable
    try:
        
        #Get affiliate for user
        aff = Affiliate.query.filter_by(affiliate=current_user.affiliated).first()
        
        #If one exists
        if aff:
            
            #Add earnings depending on product price
            if (len(new_primain.primain_name)-1) <= len(PRICES):
                
                aff.spent = PRICES[len(new_primain.primain_name)-1] 
            else:
                aff.spent = PRICES[-1] 
                
            db.session.commit()
    except:
        pass
    
    #Return home page
    return redirect(url_for("index"))


@app.route('/signup/<affiliate>', methods=['GET', 'POST'])
def signup_affiliate(affiliate):
    """Handles signing up via an affiliate link

    Args:
        affiliate (str): NAme of the affiliate

    Returns:
        html page: The signup page
    """
    
    #If data is submitted
    if request.method == 'POST':
        
        #Get data points
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        #Verify password is secure accoridng to NIST 2024 guidelines
        if len(password) <= 12:
            flash('Password must be atleast 12 characters long!', 'danger')
            return render_template('signup.html')
            
        #Create hashed password and user
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, email=email, email_verified=False,affiliated=affiliate)
        success=False
        try:
            
            #Try adding a new user
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            try:
                send_verification_email(email)
                flash('Signup successful! A verification email has been sent. Please verify your email.', 'success')

                success=True
                #Then redirect user to log in 
            
            except:
                
                #Inform user
                flash('Our Email Servers are Overworked. Try Again in a few Minutes.', 'danger')
                success = False
                
            if success:
                
                try:
                    
                    #Get affiliate
                    aff=Affiliate.query.filter_by(affiliate=affiliate).first()
                    
                    #Load all user_ids which signed up via affiliate and append new one
                    user_ids=json.loads(aff.user_ids)
                    user_ids.append(new_user.id)
                    
                    #Encode and save them
                    aff.user_ids=json.dumps(user_ids)
                    db.session.commit()
                    
                except:
                    
                    #If its the first refferal create a new Affiliate and save them to the DB
                    new_refferal=Affiliate(affiliate=affiliate,spent=0,payed_out=0,user_ids=json.dumps([new_user.id]))
                    db.session.add(new_refferal)
                    db.session.commit()
                
                #Then redirect user to log in        
                return redirect(url_for('login'))
            
        #Catch any errors and inform user
        except Exception as e:
            flash('Username or Email is already taken.', 'danger')
        finally:
            db.session.rollback()
            if not success:
                
                #Rollback
                db.session.rollback()
                
                #Query for the user you want to delete (assuming new_user has a unique identifier like an id)
                user_to_delete = User.query.filter_by(id=new_user.id).first()

                #Check if user exists and delete
                if user_to_delete:
                    db.session.delete(user_to_delete)
                    db.session.commit()

    #If get request... jsut render the page
    return render_template('signup.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user signup.

    Returns:
        html page: Renders the signup template.
    """
    
    #If data is submitted
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        #Verify password is secure accoridng to NIST 2024 guidelines
        if len(password) <= 12:
            flash('Password must be atleast 12 characters long!', 'danger')
            return render_template('signup.html')
        
        #Create hashed password and user
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, email=email, email_verified=False, affiliated="")
        success=False
        try:
            
            #Try adding a new user
            db.session.add(new_user)
            db.session.commit()
            
            # Send verification email
            try:
                
                send_verification_email(email)
                flash('Signup successful! A verification email has been sent. Please verify your email.', 'success')

                success=True
                #Then redirect user to log in 
                return redirect(url_for('login'))
            
            except:
                flash('Our Email Servers are Overworked. Try Again in a few Minutes.', 'danger')
        
        #Catch any errors and inform user
        except:
                
            flash('Username or Email is already taken.', 'danger')
        
        finally:
            
            if not success:
                
                #Rollback
                db.session.rollback()
                
                #Query for the user you want to delete (assuming new_user has a unique identifier like an id)
                user_to_delete = User.query.filter_by(id=new_user.id).first()

                #Check if user exists and delete
                if user_to_delete:
                    db.session.delete(user_to_delete)
                    db.session.commit()
    
    #If get request... just render the page
    return render_template('signup.html')


@app.route('/verify_email/<token>')
def verify_email(token):
    """Verifies the user's email.

    Args:
        token (str): The verification token.

    Returns:
        html page: Redirects to login page after verification.
    """
    
    #If token is invalid inform and redirect the user
    try:
        email = confirm_verification_token(token)
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    #Search for user (if not found throw 404)
    user = User.query.filter_by(email=email).first_or_404()
    
    #If user is already verified
    if user.email_verified:
        flash('Account already verified. Please login.', 'success')
    else:
        
        #Set verified to true and save it to the db + inform the user
        user.email_verified = True
        db.session.commit()
        flash('Your account has been verified! You can now log in.', 'success')
    
    #Redirect user to login for a quicker signup
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login.

    Returns:
        html page: Renders the login template.
    """
    
    #If data was submitted
    if request.method == 'POST':
        
        #Retrive values
        username = request.form['username']
        password = request.form['password']
        
        #Search for user
        user = User.query.filter_by(username=username).first()

        #If user exists and password is right
        if user and check_password_hash(user.password, password):
            
            #If user is also verified log them in
            if user.email_verified:
                login_user(user)
                return redirect(url_for('index'))
            
            #otherwise inform them to verify
            else:
                flash('Please verify your email before logging in.', 'danger')
                
        #Inform them of invalid credentials
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    #If its just a get request render the site
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logs out the current user.

    Returns:
        html page: Redirects to landing page.
    """
    
    logout_user()
    flash('You have been logged out.', 'warning')
    
    #Redirect to landing page
    return redirect('/')

def convert_signature_to_hex(signature_ints):
    """Convert a list of integers (signature) to a hexadecimal string. (Used for Solana signatures)

    Args:
        signature_ints (list): A list of 64 integers (0-255).

    Returns:
        str: Hexadecimal representation of the signature, or None if invalid.
    """
    
    #Check if the input is a list of 64 integers
    if isinstance(signature_ints, list) and len(signature_ints) == 64:
        
        #If the list only consists of ints smaller than 255
        if all(isinstance(i, int) and 0 <= i <= 255 for i in signature_ints):
            
            #Convert to bytes and return hex of these bytes
            signature_bytes = bytes(signature_ints)
            return signature_bytes.hex()
        
    #Return None if invalid format   
    return None 


@app.route('/check_primain_availability')
def check_primain_availability():
    """Check if Primain is already taken (used for the registration checkmark/cross logic)

    Returns:
        json: Returns availability status
    """
    
    #Remove any capital letters
    primain_name = request.args.get('primain_name').lower()

    #If the Primain isnt empty 
    if primain_name:
        
        # Check if the Primain already exists in the database
        primain = Primain.query.filter_by(primain_name=primain_name).first()

        #If it does exist set avilabilty as false
        if primain:
            
            #If subscription is not valid anymore
            if not check_subscription_status(primain.subscription_id):
                
                #Delete it and mark it as available 
                db.session.delete(primain)
                db.session.commit()
                
                return jsonify({'available': True})
                
            return jsonify({'available': False})
        
        #otherwise note avilability
        else:
            return jsonify({'available': True})  
        
    #If there is no input mark it as unavaliable as empty primains cant be registered
    else:
        return jsonify({'available': False})
    
    
@app.route('/check_username_availability')
def check_username_availability():
    """Check if username is still available (serves checkmark/cross logic in new username section)

    Returns:
        json: Availibility
    """
    
    #Get username
    username = request.args.get('username')
    
    #If its not none
    if username:
        
        #Check if the user already exists in the database
        user = User.query.filter_by(username=username).first()

    	#If it does mark it as unavailable
        if user:
            return jsonify({'available': False}) 
        
        #Else mark as available
        else:
            return jsonify({'available': True}) 
    
    #If username is empty its invalid because everyone needs to have a username
    else:
        return jsonify({'available': False})


@app.route('/delete_adress<primain_name>', methods=['DELETE', 'GET'])
@login_required
def delete_address(primain_name):
    """Display the address of the inputted Primain name.

    Args:
        primain_name (str): Name of the Primain for which to find the address.

    Returns:
        html page: Html page filled with either address data or an error.
    """
    
    #If just the page for the primain deletion is requested
    if request.method == 'GET':
        
        #Retrieve Primain and its addresses
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        
        #If there is a Primain under this name
        if primain:
            
            #If subscription expired
            if not check_subscription_status(primain.subscription_id):
                
                #Delete from Db and mark as inactive
                db.session.delete(primain)
                db.session.commit()
                
                return render_template('delete_adresses.html', 
                                address=None, 
                                primain_name=primain_name, 
                                network=None, 
                                error='No Addresses linked to this Primain')
            
            #Render the template with the addresses and the Primain name
            return render_template('delete_adresses.html', 
                                address=json.loads(primain.address), 
                                primain_name=primain_name,
                                network=json.loads(primain.chain), 
                                error=None)
        
        #If there is no associated Primain
        else:
            
            #Render the template with an error message
            return render_template('delete_adresses.html', 
                                address=None, 
                                primain_name=primain_name, 
                                network=None, 
                                error='No Addresses linked to this Primain')
    
    #If data is submitted (deletion request)
    else:
        
        try:
            
            #Get data
            data = request.get_json()
            primain_name = data.get('primain_name')
            address_to_delete = data.get('address')
            chain_to_delete = data.get('chain')
            
            #Fetch the Primain for the current user
            primain = Primain.query.filter_by(primain_name=primain_name, user_id=current_user.id).first()

            #If User does not own the Primain they want to delete an address from
            if not primain:
                return jsonify({'error': 'Primain not found or you do not have permission to delete this address.'}), 404
            
            #If subscription expired        
            if not check_subscription_status(primain.subscription_id):
                
                #Delete Primain
                db.session.delete(primain)
                db.session.commit()
                return jsonify({'error': 'Primain not found or you do not have permission to delete this address.'}), 404
                
            #Load existing addresses, chains, proofs, and signatures
            existing_addresses = json.loads(primain.address)
            existing_chains = json.loads(primain.chain)
            existing_proofs = json.loads(primain.proof)
            existing_signatures = json.loads(primain.signature)

            #Check if the address and chain combination to delete, exists in the Primain
            if address_to_delete not in existing_addresses or chain_to_delete not in existing_chains:
                return jsonify({'error': 'Address or Chain not found in this Primain.'}), 404

            #Get the index of the address and chain to delete
            index_to_delete = None
            for i in range(len(existing_addresses)):
                if existing_addresses[i] == address_to_delete and existing_chains[i] == chain_to_delete:
                    index_to_delete = i
                    break

            #If there is no match inform the user
            if index_to_delete is None:
                return jsonify({'error': 'No matching address and chain combination found.'}), 404

            #Remove the corresponding address, chain, proof, and signature
            del existing_addresses[index_to_delete]
            del existing_chains[index_to_delete]
            del existing_proofs[index_to_delete]
            del existing_signatures[index_to_delete]
            
            #Update the Primain with the new data
            primain.address = json.dumps(existing_addresses)
            primain.chain = json.dumps(existing_chains)
            primain.proof = json.dumps(existing_proofs)
            primain.signature = json.dumps(existing_signatures)

            #Commit the changes to the database
            db.session.commit()

            #Inform user
            return jsonify({'message': 'Address and chain deleted successfully'}), 200

        #If an error occurs catch it and rollback the Database
        except Exception as e:
            db.session.rollback()
            
            #Output the deletion error
            return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.route('/<primain_name>')
def display_address(primain_name):
    """Display the address of the inputted Primain name.

    Args:
        primain_name (str): Name of the Primain for which to find the address.

    Returns:
        html page: Html page filled with either address data or an error.
    """
    
    #Query the database to find the Primain with the given name
    primain = Primain.query.filter_by(primain_name=primain_name.lower()).first()
        
            
    #If the Primain is registered
    if primain:

        #If subscription expired
        if not check_subscription_status(primain.subscription_id):
            
            #Delete Primain and return empty template
            db.session.delete(primain)
            db.session.commit()
            return render_template('display_address.html', 
                                address=None, 
                                primain_name=primain_name, 
                                network=None, 
                                error='No Addresses linked to this Primain')
        
        #Create verification data
        data = (
            f"Primain name: {primain_name}\n"
            f"Primain Addresses: {primain.address}\n"
            f"Blockchain Networks: {primain.chain}\n"
            f"User Proofs: {primain.proof}\n"
            f"Backend Signatures: {primain.signature}\n"
            f"Public Key: {crypto_methods.serialize_public_key_to_string(crypto_methods.load_keys()[1])}\n"
            f"Structure of signed string that was signed: primain_name + primain.address + primain.chain + primain.proof"
        )
        
        #Render the template with the address and the Primain name
        return render_template('display_address.html', 
                               address=json.loads(primain.address), 
                               primain_name=primain_name,
                               network=json.loads(primain.chain), 
                               data=data, 
                               error=None)
        
    #If the primain is not registered
    else:
        
        #Render the template with an error message
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
    
    #If user searches for a primain
    if request.method == 'POST':
        
        #Get name of the primain
        primain_name = request.form['primain_name']
        primain = Primain.query.filter_by(primain_name=primain_name).first()
        
        #If primain is registered redirect the user to the primans page
        if primain:
            
            #if Subscription is expired
            if not check_subscription_status(primain.subscription_id):
                
                #Remove primain from the DB
                db.session.delete(primain)
                db.session.commit()
                primain = None
                
            return redirect(url_for('display_address', primain_name=primain_name))
        
        #Otherwise alert the user
        else:
            
            flash('No Wallets Associated with this Primain', 'danger')
            return render_template('get_address.html')

    #Return the page up on get request
    return render_template('get_address.html')


@app.route('/view_owned_primains')
@login_required
def view_owned_primains():
    """Returns html page with all owned Primains.

    Returns:
        html page: Page filled with owned Primains or an error.
    """
    
    #If user owns Primains, display them
    if current_user.primains:
        return render_template('view_owned_primains.html', primains=current_user.primains)
    
    #Otherwise show error
    else:
        return render_template('view_owned_primains.html')


@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    """Change username via the form in manage account

    Returns:
        html file: The manage_account page
    """
    
    #Get new username and password
    new_username = request.form['username']
    password = request.form['password']
    
    #Check if password matches
    user = current_user
    if check_password_hash(user.password, password):
        
        #Changes username
        user.username=new_username
        try:
            
            #If username is still free change it and inform the user
            db.session.commit()
            flash('Updated username!', 'success')
            return redirect(url_for('manage_account'))
        
        #If username was already taken the excpet will be triggered
        except:
            
            #Rollback the username change and inform user of error
            db.session.rollback()
            flash('Username is already taken!', 'danger')
            return redirect(url_for('manage_account'))
    
    #If password is invalid inform user
    else:
        flash("Password invalid!","danger")

    #Refresh page
    return redirect(url_for('manage_account'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Allows the user to change their password via the manage account form

    Returns:
        html page: The account page
    """
    
    #Retrive passwords
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    
    #Verify new password is secure according to NIST 20204 guidelines
    if len(new_password) <= 12:
        flash('Password must be atleast 12 characters long!', 'danger')
        return redirect(url_for('manage_account'))

    #set user and verify if old password is valid
    user = current_user
    if check_password_hash(user.password, current_password):
        
        #Hash and store the new password
        user.password = generate_password_hash(new_password, method='scrypt')
        db.session.commit()
        
        #inform user
        flash('Your password has been updated!', 'success')
    
    #inform user if passsord was invalid
    else:
        flash('Entered password is invalid!', 'danger')
        
    #Refresh account page
    return redirect(url_for('manage_account'))


@app.route('/manage_account')
@login_required
def manage_account():
    """Returns the manage account page for the current user

    Returns:
        html page: The manage account page
    """
    
    #Render page for logged in user
    user_name = current_user.username
    
    #Retrieve how much user made by affiliate marketing
    try:
        af=Affiliate.query.filter_by(affiliate=user_name).first()
        balance=af.spent-af.payed_out
    except AttributeError:
        balance=0
        
    #10% commission
    balance=balance*0.1
    
    return render_template('manage_account.html', user_name=user_name, earned=balance, primains=current_user.primains)


@app.route('/TOS')
def terms_of_service():
    """Returns the TOS page

    Returns:
        html file: The TOS page
    """
    return render_template("TOS.html")


@app.route('/contact')
def contact():
    """Returns the contact form

    Returns:
        html file: The contact page
    """
    return render_template("contact.html")

@app.route('/submit_contact_form', methods=['POST'])
def submit_contact_form():
    """Handles contact form submission

    Returns:
        html file: The contact page
    """
    
    #Retrieve form data
    email=request.form["email"]
    name=request.form["name"]
    message=request.form["message"]
    
    #Create message
    msg = Message(
        f'Support Request from {name}',#Subject
        recipients=["anton.graller@swupelpms.com"],#Recipient
    )
    
    #Create message
    msg.html = f"""
    <html>
        <body>
            <p>Email of person in need: {email}</p>
            <p>Name of person in need: {name}</p>
            <p>Message of person in need: {message} </p>
        </body>
    </html>
    """
    
    #Send message 
    mail.send(msg)
    
    #Inform user and refresh page
    flash('We have received your Message and we will get back to you via the provided email!', 'success')
    return render_template("contact.html"), 201


#Run file if executed directly
if __name__ == '__main__':
    
    #Create/Load database and then run app
    with app.app_context():
        db.create_all()
        
    app.run()
