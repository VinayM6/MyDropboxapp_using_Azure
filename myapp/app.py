from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import os

# Initialize the Flask application
app = Flask(__name__)

# Set secret key for session management from environment variable or default
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Configure SQLite database URI from environment variable or default
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///db.sqlite3')

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)

# Create a LoginManager instance and initialize it with the Flask app
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Set the login view for unauthorized access

# Define a User model inheriting from UserMixin and db.Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Primary key column
    username = db.Column(db.String(150), unique=True, nullable=False)  # Username column
    password = db.Column(db.String(150), nullable=False)  # Password column

# Define the user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Retrieve user by ID

# Configure the Azure Blob Storage connection string from environment variable
connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING', 'your_default_connection_string')
blob_service_client = BlobServiceClient.from_connection_string(connect_str)  # Initialize BlobServiceClient

# Ensure the 'uploads' directory exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

@app.route('/')
def index():
    return render_template('index.html')  # Render the index page

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']  # Get the username from the form
        password = request.form['password']  # Get the password from the form
        user = User.query.filter_by(username=username).first()  # Query the user by username
        if user and check_password_hash(user.password, password):  # Verify the password
            login_user(user)  # Log the user in
            return redirect(url_for('dashboard'))  # Redirect to the dashboard
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')  # Render the login page

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']  # Get the username from the form
        password = request.form['password']  # Get the password from the form
        hashed_password = generate_password_hash(password, method='sha256')  # Hash the password
        new_user = User(username=username, password=hashed_password)  # Create a new user
        db.session.add(new_user)  # Add the new user to the session
        db.session.commit()  # Commit the session to the database
        return redirect(url_for('login'))  # Redirect to the login page
    return render_template('register.html')  # Render the register page

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        file = request.files['file']  # Get the file from the form
        if file:
            filename = secure_filename(file.filename)  # Secure the filename
            file.save(os.path.join('uploads', filename))  # Save the file locally
            blob_client = blob_service_client.get_blob_client(container='mycontainer', blob=filename)
            with open(os.path.join('uploads', filename), 'rb') as data:
                blob_client.upload_blob(data)  # Upload the file to Azure Blob Storage
            flash('File uploaded successfully', 'success')
    return render_template('dashboard.html')  # Render the dashboard page

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log the user out
    return redirect(url_for('index'))  # Redirect to the index page

if __name__ == '__main__':
    db.create_all()  # Create the database tables
    app.run(debug=True)  # Run the Flask app in debug mode
