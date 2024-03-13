from flask import request, jsonify
from loggers.logger import logger_instance
from werkzeug.security import generate_password_hash
import random
from database_renote.operations import db_methods
from utils import redis_config
from azure.storage.blob import BlobServiceClient
from werkzeug.utils import secure_filename
import re
from datetime import datetime
from methods.customExceptions import forgot_password_exception,reset_password_exception,signin_exception,signup_exception
# import logging
# from logging.handlers import TimedRotatingFileHandler

utils_instance=redis_config()
# logger_object= logger_class()
# logger_instance=logger_object.setup_logger()
db_instance = db_methods()

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

a=utils_instance.app_object

# logger = logging.getLogger("my_logger")
# logger.setLevel(logging.INFO)
# log_formatter  = logging.Formatter("%(asctime)s,%(levelname)s,%(message)s")
# file_handler = TimedRotatingFileHandler("renote_logins_logs", when='midnight', interval=1, backupCount=90)
# file_handler.setFormatter(log_formatter)
# file_handler.setLevel(logging.INFO)
# logger.addHandler(file_handler)

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
        phone_number_pattern= r'^\d{10,13}$'
        return re.match(phone_number_pattern,phone_number)
    def validate_name(self,First_Name):
        fullname_pattern=r'^[a-z A-Z]+$'
        return re.match(fullname_pattern,First_Name)
    def validate_lastname(self,Last_Name):
        fullname_pattern=r'^[a-z A-Z]+$'
        return re.match(fullname_pattern,Last_Name)
    def password_strength_validation(password):
        
        password_validation_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}|:<>?~-]).{8,}$'
        return bool(re.match(password_validation_pattern, password))
        
    def validation_header(self):
        if 'Application' in request.headers and 'Clientid' in request.headers:
            self.application_id = request.headers['Application']
            self.client_id = request.headers['Clientid']
            #logger.info("headers assigned successfully in validation_header method")
            if self.application_id != 'renote' or self.client_id != 'necun':
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
                logger_instance.error("One or more of the request headers are invalid or missing in validation_header method")
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
                logger_instance.error("missing required headers in validation_header method")
                return jsonify(error_response), 400
        
    def signup(self):
        
        method_response=self.validation_header()
        if method_response is not None:
            return method_response
        
        data = request.json
        print("Headers Received:", request.headers)
        required_fields = ['First_Name','Last_Name', 'username', 'password', 'email', 'phone_number']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        
        raw_password = data.get('password')
        if all_methods.password_strength_validation(raw_password) == False:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Invalid password",
                    "messageKey": "invalid-password-txt",
                    "details": "The password provided is not strong enough.",
                    "type": "ValidationException",
                    "code": 400107,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"
                }
            }
            logger_instance.error("error log before log for testing")
            logger_instance.error(f"invalid password {raw_password}")
            return jsonify(error_response), 400
            
        
        

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
            logger_instance.INFO("error log before log for testing")
            logger_instance.error(f"fields missing {missing_fields}")
            return jsonify(error_response), 400

        

        user_id=self.generate_unique_user_id()
        First_Name = data['First_Name']
        Last_Name=data['Last_Name']
        username = data['username']
        password = data['password']
        email = data['email']
        phone_number = data['phone_number']
        profile_pic=' '
        logger_instance.warning(password)
        # if First_Name == Last_Name:
        #     error_response={
        #         "error": {
        #             "status": "400",
        #             "message": "Firstname and Lastname should not be same",
        #             "messageKey": "Invalid firstname or lastname",
        #             "details": "Both firstname and lastname should not be same",
        #             "type": "ValidationException",
        #             "code": 400108,
        #             "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
        #             "instance": "/v1/"  # Optional, include if relevant to your application
        #         }
        #     }
        #     logger_instance.error("firstname and lastname are same in signup method")
        #     return jsonify(error_response), 400
        method_response1=Validations_obj.firstName_Lastname_checker(First_Name,Last_Name)
        if method_response1 is not None:
            return method_response1
        
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
            logger_instance.info("error log before log for testing")
            logger_instance.error("this is error log")
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
            logger_instance.error("invalid phonenumber in signup method")
            
            return jsonify(error_response), 400


        if not self.validate_name(First_Name):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "First Name must contain only Alphabets",
                    "messageKey": "First name-alphabets-only-txt",
                    "details": "The First name provided contains invalid characters. It must only include alphabets.",
                    "type": "ValidationException",
                    "code": 400106,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("invalid firstname in signup method")
            return jsonify(error_response), 400

        if not self.validate_name(Last_Name):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "last Name must contain only Alphabets",
                    "messageKey": "Last-name-alphabets-only-txt",
                    "details": "The Last name provided contains invalid characters. It must only include alphabets.",
                    "type": "ValidationException",
                    "code": 400106,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("invalid firstname in signup method")
            return jsonify(error_response), 400
        # if not self.password_strength_validation(password):
        #     print("not working")
        #     error_response = {
        #         "error": {
        #             "status": "400",
        #             "message": "Password must contain a Uppercase,Lowercase,Number and a special character",
        #             "messageKey": "password-strength",
        #             "details": "The password provided is not strong enough. ",
        #             "type": "ValidationException",
        #             "code": 400107,
        #             "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
        #             "instance": "/v1/"  # Optional, include if relevant to your application
        #         }
        #     }
        #     logger_instance.error("Password strength exception in signup method")
        #     return jsonify(error_response), 400
        
        method_response7=Validations_obj.validation_passwordStrength(password)
        if method_response7 is not True:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password must contain a Uppercase,Lowercase,Number and a special character",
                    "messageKey": "password-strength",
                    "details": "The password provided is not strong enough. ",
                    "type": "ValidationException",
                    "code": 400107,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Password strength exception in signup method kiuyghojhgcvhjk111111111111")
            return jsonify(error_response), 400
        else:
            password=generate_password_hash(password)

        response=db_instance.signup_db_operation(self.application_id, self.client_id, user_id, username, password, email , First_Name,Last_Name, phone_number , profile_pic, 0)
        if response is not None:
            return response
        success_response = {
                "status": "201",
                "message": "User created successfully",
                "messageKey": "user-created-successfully",
                "entity_id":user_id,
                "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
        }
        logger_instance.info("user created successfully in signup method")
        return jsonify(success_response), 201


    def signin(self,a):
        data = request.json

        username = data['username']
        password = data['password']
        
        method_response=self.validation_header()
        if method_response is not None:
            return method_response
        
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
            logger_instance.error("username is missing in signin method")
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
            logger_instance.error("password is missing in signin method")
            return jsonify(error_response), 400

        response=db_instance.signin_db_operation(username,password,a)
        if response is not None:
            return response
    def forgot_password(self):
        email = request.json.get('email')
        
        method_response=self.validation_header()
        if method_response is not None:
            return method_response
        
        if not email:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Email missing",
                    "messageKey": "email-missing",
                    "details": "The email address  is Missing. Please provide email address.",
                    "type": "Missing field",
                    "code": 400301,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Email is missing in forgot_password method")
            return jsonify(error_response), 400
        
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
            logger_instance.error("invalid email in forgot_password method")
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
            logger_instance.error("Email is missing in forgot_password method")
            return jsonify(error_response), 400


        response=db_instance.get_user_by_email(email)
        if response is not None:
            return response

    def reset_password(self,token):
        
        #method_response=self.validation_header()
        #if method_response is not None:
        #  return method_response
        
        response=db_instance.user_by_reset_token(token)
        if response is not None:
            return response

    def update_password(self):
        token=request.form.get('token')
        
        # method_response=self.validation_header()
        # if method_response is not None:
        #     return method_response
        
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
            logger_instance.error("token is missing in update_password method")
            return jsonify(error_response), 401
        
        new_password=request.form.get('password')
        confirm_password=request.form.get('confirm_password')
        if not new_password or confirm_password:
            logger_instance.error("password missing in update_password method")
        if new_password != confirm_password:
            logger_instance.error("password are not matching error in update_password method")
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Passwords do not match",
                    "messageKey": "passwords-do-not-match",
                    "details": "The passwords provided do not match.",
                    "type": "ValidationException",
                    "code": 400402,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400
        
        raw_password = new_password
        if all_methods.password_strength_validation(raw_password) == False:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password too weak",
                    "messageKey": "password-too-weak",
                    "details": "The password provided is too weak.",
                    "type": "ValidationException",
                    "code": 400403,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400
                
        
        response=db_instance.db_method_update_password(token,new_password)
        if response is not None:
            return response

    def upload_image(self,username):
        
        method_response=self.validation_header()
        if method_response is not None:
            return method_response
        
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
            logger_instance.error("image is missing in upload_image method")
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
            logger_instance.error("file is not selected error in upload_image method")
            return jsonify(error_response), 400


        filename = secure_filename(file.filename)
        image_url = self.upload_to_azure_blob(file, filename)

        response=db_instance.uploading_image_url(username , image_url)
        if response is not None:
            return response

    def upload_to_azure_blob(self,file_stream, file_name):

        if not AZURE_STORAGE_CONNECTION_STRING:
            logger_instance.error("invalid Azyre connection string in upload_to_azure_blob method")
            raise ValueError("The Azure Storage Connection String is not set or is empty.")
            

        blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file_name)

        blob_client.upload_blob(file_stream, overwrite=True)

        return blob_client.url