from flask import request, jsonify
from werkzeug.security import generate_password_hash
import random  
from database_renote.operations import db_methods   
from utils import redis_config
from azure.storage.blob import BlobServiceClient
from werkzeug.utils import secure_filename
import re

utils_instance=redis_config()

db_instance = db_methods()

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

a=utils_instance.app_object

AZURE_STORAGE_CONNECTION_STRING = 'DefaultEndpointsProtocol=https;AccountName=necunblobstorage;AccountKey=hgzRK0zpgs+bXf4wnfvFLEJNbSMlbTNeJBuhYHS9jcTrRTzlh0lVlT7K59U8yG0Ojh65p/c4sV97+AStOXtFWw==;EndpointSuffix=core.windows.net'
CONTAINER_NAME = 'pictures'

class all_methods:
    def hello(self):
        print("hellloo000000000 world")
        
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        
    def generate_unique_user_id(self):
        return random.randint(10**15, (10**16)-1)
    def validate_email(email):
        email_pattern= r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern,email)
    
    def validate_phonenumber(phone_number):
        phone_number_pattern= r'^\d{10}$'
        return re.match(phone_number_pattern,phone_number)
    
    def validate_fullname(fullname):
        fullname_pattern=r'^[a-zA-Z]$'
        return re.match(fullname_pattern,fullname)
    
    def signup(self):
        data = request.json
        print("Headers Received:", request.headers)
        required_fields = ['fullname', 'username', 'password', 'email', 'phone_number']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
    
        if missing_fields:
            return jsonify({'message': 'Missing fields', 'missing': missing_fields}), 400
    
        if 'Application' in request.headers and 'Clientid' in request.headers:
            application_id = request.headers['Application']
            client_id = request.headers['Clientid']
        else:
            print("Required headers not found")
    
        user_id=self.generate_unique_user_id()      
        fullname = data['fullname']
        username = data['username']
        password = generate_password_hash(data['password'])
        email = data['email']
        phone_number = data['phone_number'] 
        profile_pic=' '
        
        if not self.validate_email(email):
            return jsonify({'message':'Invalid Email format'}), 400
        
        if not self.validate_phonenumber(phone_number):
            return jsonify ({'message':'Invalid phone number'}), 400
        
        if not self.validate_fullname(fullname):
            return jsonify({'message':'Full Name must contain only Alphabets'}), 400
            
            
    
        response=db_instance.signup_db_operation(application_id, client_id, user_id, username,  password, email , fullname, phone_number , profile_pic, 0)
        if response is not None:
            return response
        return jsonify({'message': 'User created successfully'}), 201
    
    def signin(self,a):
        data = request.json
   
        username = data['username']
        password = data['password']
        
        if not username:
            return jsonify({'message':'Username is  missing'}), 400
        
        if not password:
            return jsonify({'message':'Password is missing '}), 400
        
        response=db_instance.signin_db_operation(username,password,a)
        if response is not None:
            return response
        
    def forgot_password(self):
        email = request.json.get('email')
        if self.validate_email(email):
            return jsonify({'message':'Email invalid'}), 400
        if not email:
            return jsonify({'message':'Email is required'}), 400 
        
        response=db_instance.get_user_by_email(email)
        if response is not None:
            return response
    
    def reset_password(self,token):
        response=db_instance.user_by_reset_token(token)
        if response is not None:
            return response
        
    def update_password(self):
        token=request.form.get('token')
        if not token:
            return jsonify({'message':'token invalid'}), 401
        new_password=request.form.get('password')
        confirm_password=request.form.get('confirm_password')
        if not new_password or confirm_password:
            if new_password != confirm_password:
                return jsonify({'message':'passwords do not match'}), 400
        
        response=db_instance.db_method_update_password(token,new_password)
        if response is not None:
            return response
        
    def upload_image(self,username):
        if 'image' not in request.files:
            return jsonify({'message': 'No image part'}), 400
 
        file = request.files['image']
        if file.filename == '' or not self.allowed_file(file.filename):
            return jsonify({'message': 'No selected file'}), 400
    
        filename = secure_filename(file.filename)
        image_url = self.upload_to_azure_blob(file, filename)
        
        response=db_instance.uploading_image_url(username , image_url)
        if response is not None:
            return response 
    
        
    
    def upload_to_azure_blob(self,file_stream, file_name):
   
        if not AZURE_STORAGE_CONNECTION_STRING:
            raise ValueError("The Azure Storage Connection String is not set or is empty.")
    
        blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file_name)
    
        blob_client.upload_blob(file_stream, overwrite=True)
    
        return blob_client.url