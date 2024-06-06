from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import lazyload
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from flask_login import login_required, current_user
from flask_login import LoginManager
from flask_login import login_user
import crypto_methods
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    public_key = db.Column(db.String(100), unique=True, nullable=False)
    primains = relationship('Primain', backref='owner', lazy=True)

class Primain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    primain_name = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    proof = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        public_key = request.form['public_key']
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, public_key=public_key)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # Rollback the session in case of error
            if isinstance(e.orig, sqlite3.IntegrityError):
                if "UNIQUE constraint failed: user.username" in str(e.orig):
                    flash('Username already exists. Please choose a different one.', 'danger')
                elif "UNIQUE constraint failed: user.public_key" in str(e.orig):
                    flash('Only one account per public key!', 'danger')
                else:
                    flash('An error occurred during signup. Please try again.', 'danger')
            else:
                flash('An error occurred during signup. Please try again.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register_primain', methods=['GET', 'POST'])
@login_required
def register_primain():
    if request.method == 'POST':
        primain_name = request.form['primain_name']
        proof = request.form['proof']
        address = request.form['address']
        
        if len(current_user.primains) >= 3:
            flash('You can only own a maximum of 3 primains.', 'danger')
            return redirect(url_for('register_primain'))

        new_primain = Primain(primain_name=primain_name, address=address, proof=proof, user_id=current_user.id)
        message = f"{primain_name}{address}"

        try:
            valid = crypto_methods.verify_signature(proof, message, address)
            if valid:
                try:
                    db.session.add(new_primain)
                    db.session.commit()
                    flash('Primain registration successful!', 'success')
                    return redirect(url_for('index'))
                except:
                    flash('Primain Name is Already Taken!', 'danger')
            else:
                flash('Data is invalid!', 'danger')
        except:
            flash('Data is invalid!', 'danger')
           
    return render_template('register_primain.html')

@app.route('/view_owned_primains')
@login_required
def view_owned_primains():
    user = current_user
    if user is None:
        flash('User not found in the database. Please login again.', 'danger')
        return redirect(url_for('login'))

    primains = user.primains
    if primains:
        return render_template('view_owned_primains.html', primains=primains)
    else:
        flash('No Primains found for this user.', 'info')
        return render_template('view_owned_primains.html')

@app.route('/help')
@login_required
def help():
    return render_template('help.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
