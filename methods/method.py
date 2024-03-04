from flask import request, jsonify
from werkzeug.security import generate_password_hash
import random
from database_renote.operations import db_methods
from utils import redis_config
from azure.storage.blob import BlobServiceClient
from werkzeug.utils import secure_filename
import re
from datetime import datetime
from methods.customExceptions import forgot_password_exception,reset_password_exception,signin_exception,signup_exception

utils_instance=redis_config()

db_instance = db_methods()

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

a=utils_instance.app_object

AZURE_STORAGE_CONNECTION_STRING = 'DefaultEndpointsProtocol=https;AccountName=necunblobstorage;AccountKey=hgzRK0zpgs+bXf4wnfvFLEJNbSMlbTNeJBuhYHS9jcTrRTzlh0lVlT7K59U8yG0Ojh65p/c4sV97+AStOXtFWw==;EndpointSuffix=core.windows.net'
CONTAINER_NAME = 'pictures'

class all_methods:
    def hello(self):
        print("hellloo000000000 world")
    def allowed_file(self,filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    def generate_unique_user_id(self):
        return random.randint(10**15, (10**16)-1)
    def validate_email(self,email):
        email_pattern= r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern,email)
    def validate_phonenumber(self,phone_number):
        phone_number_pattern= r'^\d{10}$'
        return re.match(phone_number_pattern,phone_number)
    def validate_name(self,First_Name):
        fullname_pattern=r'^[a-z A-Z]+$'
        return re.match(fullname_pattern,First_Name)
    def validate_lastname(self,Last_Name):
        fullname_pattern=r'^[a-z A-Z]+$'
        return re.match(fullname_pattern,Last_Name)
    def password_strength_validation(self,password):
            return len(password) > 7
    def signup(self):
        data = request.json
        print("Headers Received:", request.headers)
        required_fields = ['First_Name','Last_Name', 'username', 'password', 'email', 'phone_number']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]

        if missing_fields:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Missing fields",
                    "messageKey": "missing-fields-txt",
                    "details": f"The following fields are missing: {missing_fields}",
                    "type": "ValidationException",
                    "code": 400103,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"
                }
            }
            return jsonify(error_response), 400


        if 'Application' in request.headers and 'Clientid' in request.headers:
            application_id = request.headers['Application']
            client_id = request.headers['Clientid']
            if application_id != 'renote' or client_id != 'necun':
                error_response = {
                        "error": {
                        "status": "400",
                        "message": "Headers Invalid",
                        "messageKey": "invalid-headers-txt",
                        "details": "One or more of the request headers are invalid or missing.",
                        "type": "HeaderValidationException",
                        "code": 400104,
                        "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/"  # Optional, include if relevant to your application
                    }
                }
                return jsonify(error_response), 400
        else:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Required headers not found",
                    "messageKey": "required-headers-missing-txt",
                    "details": "The request is missing one or more required headers.",
                    "type": "HeaderValidationException",
                    "code": 400105,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        user_id=self.generate_unique_user_id()
        First_Name = data['First_Name']
        Last_Name=data['Last_Name']
        username = data['username']
        password = generate_password_hash(data['password'])
        email = data['email']
        phone_number = data['phone_number']
        profile_pic=' '

        if not self.validate_email(email):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Invalid Email format",
                    "messageKey": "invalid-email-format-txt",
                    "details": "The email address provided does not match the expected format.",
                    "type": "ValidationException",
                    "code": 400101,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400


        if not self.validate_phonenumber(phone_number):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Invalid phone number",
                    "messageKey": "invalid-phone-number-txt",
                    "details": "The phone number provided does not match the expected format.",
                    "type": "ValidationException",
                    "code": 400100,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400


        if not self.validate_name(First_Name):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "First Name must contain only Alphabets",
                    "messageKey": "full-name-alphabets-only-txt",
                    "details": "The full name provided contains invalid characters. It must only include alphabets.",
                    "type": "ValidationException",
                    "code": 400106,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        if not self.validate_name(Last_Name):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "last Name must contain only Alphabets",
                    "messageKey": "full-name-alphabets-only-txt",
                    "details": "The full name provided contains invalid characters. It must only include alphabets.",
                    "type": "ValidationException",
                    "code": 400106,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400
        if not self.password_strength_validation(password):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password must contain more than 7 letters",
                    "messageKey": "password-length",
                    "details": "The password provided is too short. It must contain more than 7 characters.",
                    "type": "ValidationException",
                    "code": 400107,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400


        response=db_instance.signup_db_operation(application_id, client_id, user_id, username,  password, email , First_Name,Last_Name, phone_number , profile_pic, 0)
        if response is not None:
            return response
        success_response = {
                "status": "201",
                "message": "User created successfully",
                "messageKey": "user-created-successfully",
                "entity_id":user_id,
                "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
        }
        
        return jsonify(success_response), 201


    def signin(self,a):
        data = request.json

        username = data['username']
        password = data['password']
        if not username:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Username is missing",
                    "messageKey": "username-missing",
                    "details": "The request did not include a username, which is required.",
                    "type": "ValidationException",
                    "code": 400202,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        if not password:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password is missing",
                    "messageKey": "password-missing",
                    "details": "The request did not include a password, which is required.",
                    "type": "ValidationException",
                    "code": 400203,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        response=db_instance.signin_db_operation(username,password,a)
        if response is not None:
            return response
    def forgot_password(self):
        email = request.json.get('email')
        if not self.validate_email(email):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Email invalid",
                    "messageKey": "email-invalid",
                    "details": "The email address provided is not valid. Please provide a valid email address.",
                    "type": "ValidationException",
                    "code": 400302,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        if not email:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Email is required",
                    "messageKey": "email-required",
                    "details": "The request did not include an email address, which is required.",
                    "type": "ValidationException",
                    "code": 400304,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400


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
            error_response = {
            "error": {
                "status": "401",
                "message": "Token missing or invalid",
                "messageKey": "token-missing-invalid",
                "details": "The request did not include a token or included an invalid token.",
                "type": "AuthenticationException",
                "code": 400401,
                "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                "instance": "/v1/"  # Optional, include if relevant to your application
            }
        }
            return jsonify(error_response), 401
        
        new_password=request.form.get('password')
        confirm_password=request.form.get('confirm_password')
        if not new_password or confirm_password:
            if new_password != confirm_password:
                return jsonify({'message':'passwords do not match'}), 400
        
        response=db_instance.db_method_update_password(token,new_password)
        if response is not None:
            return response

        response=db_instance.db_method_update_password(token,new_password)
        if response is not None:
            return response

    def upload_image(self,username):
        if 'image' not in request.files:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "No image part",
                    "messageKey": "no-image-part",
                    "details": "The request did not include an image part. Please include an image part in the request.",
                    "type": "ValidationException",
                    "code": 400600,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/upload-image"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        file = request.files['image']
        if file.filename == '' or not self.allowed_file(file.filename):
            error_response = {
            "error": {
                "status": "400",
                "message": "No selected file",
                "messageKey": "no-selected-file",
                "details": "No file was selected for upload. Please select a file to upload.",
                "type": "ValidationException",
                "code": 400601,
                "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                "instance": "/v1/upload-image"  # Optional, include if relevant to your application
            }
        }
            return jsonify(error_response), 400


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