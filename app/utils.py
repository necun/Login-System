from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
from functools import wraps
from redis import Redis
from flask_mail import Mail, Message
from redis import Redis
import mysql.connector, jwt, datetime, secrets, re, os

# Configuration settings
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['MAIL_SERVER'] ='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Regular expressions for validation
email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
phone_number_regex = r"^\d{10}$"

# Database and Redis configurations
redis_client = Redis(host='localhost', port=6379, db=0)
conn_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name='renote-login-sql-db-pool',
    pool_size=5,
    host='localhost',
    user='root',
    password= 'vishnuvardhan',
    database='renote-login-sql-db'
)

# Azure Blob Storage configuration
AZURE_STORAGE_CONNECTION_STRING = 'DefaultEndpointsProtocol=https;AccountName=necunblobstorage;AccountKey=hgzRK0zpgs+bXf4wnfvFLEJNbSMlbTNeJBuhYHS9jcTrRTzlh0lVlT7K59U8yG0Ojh65p/c4sV97+AStOXtFWw==;EndpointSuffix=core.windows.net'
CONTAINER_NAME = 'pictures'

# Function definitions
def get_db_connection():
    return conn_pool.get_connection()

def send_email(subject, recipient, body):
    message = Message(subject=subject, sender='vishnuv@necun.in', recipients=[recipient], body=body)
    mail.send(message)
    pass

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_azure_blob(file_stream, file_name):
    if not AZURE_STORAGE_CONNECTION_STRING:
        raise ValueError("The Azure Storage Connection String is not set or is empty.")

    blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file_name)

    blob_client.upload_blob(file_stream, overwrite=True)

    return blob_client.url