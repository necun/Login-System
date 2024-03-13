from flask import  request ,jsonify
from loggers.logger import logger_instance
from jose import jwt
import re
from werkzeug.security import  check_password_hash
from redis import Redis
import random
from datetime import datetime as dt
from dateutil.relativedelta import relativedelta
from utils import redis_config



ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

utils_instance = redis_config()


redis_client = Redis(host='localhost', port=6379, db=0)

class Validations:
    
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
    
    def validation_passwordStrength(self,password):
        password_validation_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}|:<>?~-]).{8,}$'
        return re.match(password_validation_pattern, password)
    
    def validateHeaders_Authorization(self):
        if not request.headers.get('Authorization'):
            logger_instance.error("Authorization header missing") 
            error_response = {
                "error": {
                    "status": "401",
                    "message": "Invalid Headers",
                    "messageKey": "invalid-headers",
                    "details": "The request did not include headers or included an invalid header.",
                    "type": "AuthenticationException",
                    "code": 401404,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Authorization header missing")
            return jsonify(error_response), 401
        
    def tokenMissing(self,token):
        if not token:
            error_response = {
                "error": {
                    "status": "401",
                    "message": "Token is missing",
                    "messageKey": "token-missing",
                    "details": "The request did not include a token or included an invalid token.",
                    "type": "AuthenticationException",
                    "code": 401405,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Token is not provided")
            return jsonify(error_response), 401
        
    def redisCheck_headersCheck(self,redis_username,token_user,token_client_id,token_application_id):
        if redis_username is None or redis_username.decode() != token_user:
                logger_instance.error("Error in redis username or token for validation")
                if token_application_id != "renote" or token_client_id != "necun":
                    logger_instance.error("error in headers or wrongly passed headers")
                    error_response = {
                        "error": {
                            "status": "401",
                            "message": "Token is invalid or expired!",
                            "messageKey": "token-invalid",
                            "details": "The token is invalid or has expired.",
                            "type": "AuthenticationException",
                            "code": 400402,
                            "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                            "instance": "/v1/"  # Optional, include if relevant to your application
                        }
                    }
                    return jsonify(error_response), 401
                
                
    def missingFields_validation(self,data):
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
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"
                }
            }
            logger_instance.error(f"fields missing {missing_fields}")
            return jsonify(error_response), 400
        
    def firstName_Lastname_checker(self,First_Name,Last_Name):
        if First_Name == Last_Name:
            error_response={
                "error": {
                    "status": "400",
                    "message": "Firstname and Lastname should not be same",
                    "messageKey": "Invalid firstname or lastname",
                    "details": "Both firstname and lastname should not be same",
                    "type": "ValidationException",
                    "code": 400108,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("firstname and lastname are same in signup method")
            return jsonify(error_response), 400
        
            
    def missingFieldValidation_username(self,username):
        if not username:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Username is missing",
                    "messageKey": "username-missing",
                    "details": "The request did not include a username, which is required.",
                    "type": "ValidationException",
                    "code": 400202,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("username is missing in signin method")
            return jsonify(error_response), 400
        
    def missingFieldValidation_password(self,password):
        if not password:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password is missing",
                    "messageKey": "password-missing",
                    "details": "The request did not include a password, which is required.",
                    "type": "ValidationException",
                    "code": 400203,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("password is missing in signin method")
            return jsonify(error_response), 400
    
    def missingFieldValidation_email(self,email):
        if not email:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Email missing",
                    "messageKey": "email-missing",
                    "details": "The email address  is Missing. Please provide email address.",
                    "type": "Missing field",
                    "code": 400301,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Email is missing in forgot_password method")
            return jsonify(error_response), 400
        
    def emailValidation(self,email):
        if not self.validate_email(email):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Invalid Email format",
                    "messageKey": "invalid-email-format-txt",
                    "details": "The email address provided does not match the expected format.",
                    "type": "ValidationException",
                    "code": 400101,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.info("error log before log for testing")
            logger_instance.error("Invalid Email format ")
            return jsonify(error_response), 400
        
    def phoneNumberValidation(self,phone_number):
        if not self.validate_phonenumber(phone_number):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Invalid phone number",
                    "messageKey": "invalid-phone-number-txt",
                    "details": "The phone number provided does not match the expected format.",
                    "type": "ValidationException",
                    "code": 400100,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("invalid phonenumber in signup method")
            return jsonify(error_response), 400
    
    def nameValidation(self,First_Name):
        if not self.validate_name(First_Name):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "firstName or lastname must contain only Alphabets",
                    "messageKey": "name-alphabets-only-txt",
                    "details": "The name provided contains invalid characters. It must only include alphabets.",
                    "type": "ValidationException",
                    "code": 400106,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("invalid firstname or lastname in signup method")
            return jsonify(error_response), 400
        
    def passwordStrengthValidation(self,password):
        logger_instance.error("password validation started    kiughuyfcfghjufdcvghjuhgfcx")
        if not self.validation_passwordStrength(password):
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password must contain a Uppercase,Lowercase,Number and a special character",
                    "messageKey": "password-strength",
                    "details": "The password provided is not strong enough. ",
                    "type": "ValidationException",
                    "code": 400107,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Password strength exception in signup method kiuyghojhgcvhjk111111111111")
            return jsonify(error_response), 400
    
    def not_newPassword_confirmPassword(self,new_password,confirm_password):
        if not new_password or confirm_password:
            logger_instance.error("password missing in update_password method")
            return jsonify({'message':'please enter new password AND CONFIRM PASSWORD'}), 400   
    def newPassword_confirmPassword_validation(self,new_password,confirm_password):
        if self.validation_passwordStrength(new_password) and self.validation_passwordStrength(confirm_password) is True:
            logger_instance.info("password validation is done in update_password")
            if new_password != confirm_password:
                logger_instance.error("password are not matching error in update_password method")
                return jsonify({'message':'passwords do not match'}), 400
        else:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Password must contain a Uppercase,Lowercase,Number and a special character",
                    "messageKey": "password-strength",
                    "details": "The password provided is not strong enough. ",
                    "type": "ValidationException",
                    "code": 400107,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Password strength exception ")
            return jsonify(error_response), 400
            
        
        
    def notImage_validation(self):
          if 'image' not in request.files:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "No image part",
                    "messageKey": "no-image-part",
                    "details": "The request did not include an image part. Please include an image part in the request.",
                    "type": "ValidationException",
                    "code": 400600,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/upload-image"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("image is missing in upload_image method")
            return jsonify(error_response), 400
    
    def filenameAndExtension_validation(self):
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
                "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                "instance": "/v1/upload-image"  # Optional, include if relevant to your application
            }
        }
            logger_instance.error("file is not selected error in upload_image method")
            return jsonify(error_response), 400
        
    def userRecord_validation(self,user_record):
        if user_record is None:  # Check if the username is not found
                error_response = {
                    "error": {
                        "status": "404",
                        "message": "User not found",
                        "messageKey": "user-login-missingPassword",
                        "details": "The username provided does not match any user in our database.",
                        "type": "LoginException",
                        "code": 404204,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/"  # Optional, include if relevant to your application
                    }
                }
                logger_instance.error("user not found in signin_db_operation method")
                return jsonify(error_response), 404
    
    def userValidationAndTokenGeneration(self,user_record,user_password,email,user_info,username,application_id,client_id,app):
        if user_record and check_password_hash(user_record[0], user_password):
                token = jwt.encode({'username': username, 'email': email, 'Application': application_id,
                                    'Clientid': client_id, 'exp': dt.utcnow() + relativedelta(minutes=30)},
                                    app.config['SECRET_KEY'])
                redis_client.hmset(token, user_info)
                redis_client.expire(token, 1800)
                success_response = {
                            "status" : 200,
                            "message" : "Login successful",
                            "messageKey" : "login-success",
                            "timestamp" : dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                            "details" :{
                                "token": str(token)
                            }
                            
                        }
                logger_instance.info("user logged In successfully in signin_db_operation")
                return jsonify(success_response), 200
        else:
                error_response = {
                    "error": {
                        "status": "400",
                        "message": "Invalid username or password",
                        "messageKey": "user-login-invalidCredentials",
                        "details": "The username or password provided is incorrect. Please try again.",
                        "type": "LoginException",
                        "code": 400201,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/"  # Optional, include if relevant to your application
                    }
                }
                logger_instance.info("Invalid username or password in signin_db_operation")
                return jsonify(error_response), 400
            
            
    def userNotFound_validation(self,user):
        if not user:
                error_response = {
                    "error": {
                        "status": "404",
                        "message": "User not found",
                        "messageKey": "error-user-not-found",
                        "details": "The specified user does not exist in our database.",
                        "type": "UserNotFoundException",
                        "code": 400204,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/"  # Optional, include if relevant to your application
                    }
                }
                logger_instance.error("User not found in get_user_by_email")
                return jsonify(error_response), 404
        
#object for Validations  class in validation.py
Validations_obj=Validations()