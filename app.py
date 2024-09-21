#Manage partial imports
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_required, current_user,login_user,LoginManager,UserMixin,logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

#Manage full imports
import crypto_methods
import sqlite3

#Configure flask app
app = Flask("Swupel Primain Service")
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

#Configure database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    """User class used to hold data of individual accounts

    Args:
        UserMixin (Class): provides default methods for user management
        db (Class): Current database model
        
    Attributes:
        id: Primary DB key
        username: Costum unique username of every user
        password: Salted and hashed password of every user
        primains: Owned Primains of every user (links to primain Class
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
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
    """Handles all requests to the signup page

    Returns:
        html page: Either login or signup html page
    """
    
    #If request is a post request (user submitted form)
    if request.method == 'POST':
        
        #Get form data
        username = request.form['username']
        password = request.form['password']
        
        #Hash password and create new user
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password)
        
        try:
            #Add new user to the DB 
            db.session.add(new_user)
            db.session.commit()
            
            #confirm and redirec if successfull
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        #If adding the new user fails
        except Exception as e:
            
            #Rollback the session and flash corresponding error
            db.session.rollback() 
            if isinstance(e.orig, sqlite3.IntegrityError):
                
                if "UNIQUE constraint failed: user.username" in str(e.orig):
                    flash('Username already exists. Please choose a different one.', 'danger')
                    
                elif "UNIQUE constraint failed: user.address" in str(e.orig):
                    flash('Only one account per public key!', 'danger')
                    
                else:
                    flash('An error occurred during signup. Please try again.', 'danger')
            else:
                flash('An error occurred during signup. Please try again.', 'danger')

    #Upon a get request just render the html page
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login method logs the user in

    Returns:
        html page: Either home or login page
    """
    
    #if user ha filled out the form
    if request.method == 'POST':
        
        #Get form data and try to retrieve user
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        #if this worked and the password is valid log user in
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
    
        #otherwise display an error
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            
    #If its a simple get request just render the login page
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
          
        #check if user has exceeded max amount of primains
        if len(current_user.primains) >= 3:
            
            #inform user if that is the case
            flash('You can only own a maximum of 3 primains.', 'danger')
            return redirect(url_for('register_primain'))
        
        #Create signature
        signature=crypto_methods.serialize_signature_to_string(crypto_methods.sign_message(f"{primain_name}{address}{chain}{proof}".encode()))

        #create new primain object and build message string 
        new_primain = Primain(primain_name=primain_name, address=address, chain=chain,proof=proof,signature=signature, user_id=current_user.id)
        message = f"{primain_name}{chain}{address}"

        try:
            
            #verify if user actually owns the address
            valid = crypto_methods.verify_signature(proof, message, address)
            
            #if thats the case
            if valid:
                
                try:
                    #try adding the new Primain to the database
                    db.session.add(new_primain)
                    db.session.commit()
                    
                    #inform user of success
                    flash('Primain registration successful!', 'success')
                    return redirect(url_for('index'))
            
                #Or flash errors depending on what went wrong 
                except:
                    flash('Primain Name is Already Taken!', 'danger')
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
        
        data=f"Primain name: {primain_name}\nPrimain Address: {primain.address}\nBlockchain Network: {primain.chain}\nUser Proof: {primain.proof} \nBackend Signature: {primain.signature} \nPublic Key: {crypto_methods.serialize_public_key_to_string(crypto_methods.load_keys(crypto_methods.PASSWORD)[1])}\nString that was signed: {primain_name}{primain.address}{primain.chain}{primain.proof}"
        # Render the template with the address and the primain name
        return render_template('display_address.html', address=primain.address, primain_name=primain_name,network=primain.chain, data=data, error=None)
    
    else:
        # Render the template with an error message
        return render_template('display_address.html', address=None, primain_name=primain_name, network=None, error='No Addresses linked to this Primain')

@app.route('/', methods=['POST','GET'])
def get_address():
    """retrieves address linked to a primain

    Returns:
        string: Address linked to the primain
    """
    
    #If user has filled out form
    if request.method == 'POST':
        
        #retrive data and qurey for inputted name
        primain_name = request.form['primain_name']
        primain = Primain.query.filter_by(primain_name=primain_name).first()

        #If this search was successfull
        if primain:
            
            # Return the address associated with the primain
            return jsonify({'address': primain.address, 'network':primain.chain})

        else:
            # If primain with the given name is not found, return an error message
            return jsonify({'error': 'No Addresses linked to this Primain'}), 404
        
    #If request was a normal get request just display the html page
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
