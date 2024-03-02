from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error as MySQLError
from mysql.connector import errorcode, pooling
import jwt
import datetime
import secrets
from redis import Redis
from utils import redis_config
from datetime import datetime as dt
from methods.customExceptions import forgot_password_exception, reset_password_exception, signin_exception, signup_exception

utils_instance = redis_config()

class db_methods:
    def get_db_connection(self):
        conn = {
            'host': 'localhost',
            'user': 'root',
            'password': 'root',
            'database': 'renote-login-sql-db'
        }
        conn_pool = mysql.connector.pooling.MySQLConnectionPool(pool_name="renote-login-sql-db-pool", pool_size=5, **conn)
        return conn_pool.get_connection()

    def signin_db_operation(self, username, password, app):
    # Check if username or password is missing
        if not username:
            error_response = {
                "error": {
                    "status": "400",
                    "message": "Username is missing",
                    "messageKey": "login-invalid-user-name",
                    "details": "Username field is empty. Please provide a username.",
                    "type": "LoginException",
                    "code": 400202,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/auth/"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 400

        if not password:
            error_response = {
                    "error": {
                        "status": "400",
                        "message": "Password is missing",
                        "messageKey": "login-missing-password",
                        "details": "Password field is empty. Please provide a password.",
                        "type": "LoginException",
                        "code": 400203,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/"  # Optional, include if relevant to your application
                    }
                }
            return jsonify(error_response), 400
        
        
        user_password = password
        conn = self.get_db_connection()
        cursor = conn.cursor(buffered=True)
        try:
            query = "SELECT password,email,phone_number FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            user_record = cursor.fetchone()

            if user_record is None:  # Check if the username is not found
                error_response = {
                    "error": {
                        "status": "404",
                        "message": "User not found",
                        "messageKey": "login-user-not-found",
                        "details": "The username provided does not match any user in our database.",
                        "type": "LoginException",
                        "code": 404204,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/"  # Optional, include if relevant to your application
                    }
                }
                return jsonify(error_response), 404

            password = user_record[0]
            email = user_record[1]
            phone_number = user_record[2]
            print(user_record)

            application_id = request.headers['Application']
            client_id = request.headers['Clientid']

            user_info = {
                'username': username,
                'Application': application_id,
                'Clientid': client_id,
                'email': email,
                'phone_number': phone_number
            }
            print(user_info)

            redis_client = Redis(host='localhost', port=6379, db=0)

            if user_record and check_password_hash(user_record[0], user_password):
                token = jwt.encode({'username': username, 'email': email, 'Application': application_id,
                                    'Clientid': client_id, 'exp': dt.utcnow() + datetime.timedelta(minutes=30)},
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
                return jsonify(success_response), 200
            else:
                error_response = {
                    "error": {
                        "status": "400",
                        "message": "Invalid username or password",
                        "messageKey": "login-invalid-credentials",
                        "details": "The username or password provided is incorrect. Please try again.",
                        "type": "LoginException",
                        "code": 400201,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/"  # Optional, include if relevant to your application
                    }
                }
                return jsonify(error_response), 400

        except mysql.connector.Error as err:
            print("Database Error:", err)
            code = signin_exception(err)  #############################
            error_response = {
                    "status": "500",
                    "code": code,  # Use the determined code
                    "message": "Database error",
                    "error": str(err),  # Convert the error object to a string to include in the response
                    "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                }
            return jsonify(error_response), 500
        finally:
            cursor.close()
            conn.close()
    def signup_db_operation(self, application_id, client_id, user_id, username, password, email, fullname, phone_number, profile_pic, status):
            conn = self.get_db_connection()
            cursor = conn.cursor()
            try:
                query = "INSERT INTO users (application_id,client_id,user_id,username,password,email,fullname,phone_number,profile_pic,status) VALUES (%s,%s,%s,%s, %s, %s, %s, %s, %s, %s)"
                cursor.execute(query, (application_id, client_id, user_id, username, password, email, fullname, phone_number, profile_pic, status))
                conn.commit()
                entity_id = cursor.lastrowid
            except MySQLError as err:
                if err.errno == errorcode.ER_DUP_ENTRY:
                    error_msg = str(err).lower()
                    if "email" in error_msg:
                        error_response = {
                            "error": {
                                "status": "409",
                                "message": "Email already exists",
                                "messageKey": "signup-email-exists",
                                "details": "The email provided is already associated with an existing account.",
                                "type": "SignupException",
                                "code": 409101,
                                "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                                "instance": "/v1/auth/signup"  # Optional, include if relevant to your application
                            }
                        }
                        return jsonify(error_response), 409
                    elif "username" in error_msg:
                        error_response = {
                            "error": {
                                "status": "409",
                                "message": "Username already exists",
                                "messageKey": "signup-username-exists",
                                "details": "The username provided is already taken by another user.",
                                "type": "SignupException",
                                "code": 409100,
                                "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                                "instance": "/v1/auth/signup"  # Optional, include if relevant to your application
                            }
                        }
                        return jsonify(error_response), 409
                    elif "phone_number" in error_msg:
                        error_response = {
                            "error": {
                                "status": "409",
                                "message": "Phone Number already exists",
                                "messageKey": "signup-phone-exists",
                                "details": "The phone number provided is already associated with another account.",
                                "type": "SignupException",
                                "code": 409102,
                                "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                                "instance": "/v1/auth/signup"  # Optional, include if relevant to your application
                            }
                        }
                        return jsonify(error_response), 409
                    else:
                        error_response = {
                            "error": {
                                "status": "409",
                                "message": "Duplicate entry for unique field",
                                "messageKey": "signup-duplicate-entry",
                                "details": "A duplicate entry for a field intended to be unique was detected.",
                                "type": "SignupException",
                                "code": 409103,
                                "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                                "instance": "/v1/auth/signup"  # Optional, include if relevant to your application
                            }
                        }
                        return jsonify(error_response), 409
                else:
                    print("Database Error:", err)
                    code = signup_exception(err)
                    error_response = {
                    "status": "500",
                    "code": str(code),
                    "message": "Failed to create user due to a database error",
                    "error": str(err),
                    "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                }
                    return jsonify(error_response), 500
            finally:
                cursor.close()
                conn.close()

    def get_user_by_email(self, email):
        conn = self.get_db_connection()
        cursor = conn.cursor(buffered=True)
        try:
            cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
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
                return jsonify(error_response), 404
            reset_token = secrets.token_hex(16)
            print(reset_token)
            cursor.execute("UPDATE users SET reset_token = %s WHERE user_id=%s", (reset_token, user[0]))
            conn.commit()
            error_response = {
                "success": {
                    "status": "200",
                    "message": "Password reset link has been sent to your mail",
                    "messageKey": "password-reset-link-sent-txt",
                    "details": {
                        'data':"A link to reset your password has been successfully sent to the email address provided.",
                        'reset_token':reset_token
                        },
                    "type": "PasswordResetNotification",
                    "code": 200405,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/auth/reset-password"
                }
            }
            return jsonify(error_response), 200

        except mysql.connector.Error as err:
            code = signin_exception(err)
            error_response = {
                "status": "500",
                "code": str(code),
                "message": "Database error",
                "error": str(err),
                "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            }
            return jsonify(error_response), 500
        finally:
            cursor.close()
            conn.close()

    def user_by_reset_token(self, token):
        conn = self.get_db_connection()
        cursor = conn.cursor(buffered=True)
        
        try:
            cursor.execute("SELECT user_id FROM users WHERE reset_token = %s", (token,))
            data=cursor.fetchone()
            if data is not None:
                return render_template('reset_password.html', token=token)
            else:
                error_response = {
                    "error": {
                        "status": "400",
                        "message": "Invalid or expired token",
                        "messageKey": "invalid-expired-token",
                        "details": "The provided token is either invalid or has expired. Please request a new one.",
                        "type": "AuthenticationException",
                        "code": 400402,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/token"  # Optional, include if relevant to your application
                    }
                }
                return jsonify(error_response), 400

        except mysql.connector.Error as err:
            code = reset_password_exception(err)
            error_response = {
                "status": "500",
                "code": code,  # Dynamically use the code returned from signin_exception
                "message": "Database error",
                "error": str(err),  # Convert the MySQL error to a string for the response
                "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            }
            return jsonify(error_response), 500
        finally:
            cursor.close()
            conn.close()

    def db_method_update_password(self, token, new_password):
        conn = self.get_db_connection()
        cursor = conn.cursor(buffered=True)

        try:
            cursor.execute("SELECT user_id FROM users WHERE reset_token = %s", (token,))
            user = cursor.fetchone()

            if user:
                hashed_password = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password =%s, reset_token=NULL WHERE user_id=%s",
                               (hashed_password, user[0]))
                conn.commit()
                success_response = {
                    "success": {
                        "status": "200",
                        "message": "Password has been updated successfully",
                        "messageKey": "password-update-success",
                        "details": "Your password has been successfully updated.",
                        "type": "PasswordUpdateSuccess",
                        "code": 200400,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/update-password"  # Optional, include if relevant to your application
                    }
                }
                return jsonify(success_response), 200

            else:
                error_response = {
                    "error": {
                        "status": "400",
                        "message": "Invalid or expired token",
                        "messageKey": "invalid-expired-token",
                        "details": "The provided token is either invalid or has expired. Please request a new one.",
                        "type": "TokenException",
                        "code": 400402,
                        "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                        "instance": "/v1/auth/token"  # Optional, include if relevant to your application
                    }
                }
                return jsonify(error_response), 400

        except mysql.connector.Error as err:
            return jsonify({'status': '500', "code": "Add Error", 'message': 'Database error',
                            'error': str(err), 'timestamp': dt.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}), 500
        finally:
            cursor.close()
            conn.close()

    def uploading_image_url(self, username, image_url):
        conn = self.get_db_connection()
        cursor = conn.cursor(buffered=True)
        try:
            query = "UPDATE users SET profile_pic=%s where username=%s"
            cursor.execute(query, (image_url, username,))
            conn.commit()
            error_response = {
                "error": {
                    "status": "200",
                    "message": "Image uploaded successfully",
                    "messageKey": "image-upload-success",
                    "details": "Your image has been successfully uploaded.",
                    "type": "ImageUploadSuccess",
                    "code": 200500,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/upload-image",
                    "url": image_url
                }
            }
            return jsonify(error_response), 200
        except mysql.connector.Error as err:
            print("Error:", err)
            error_response = {
                "error": {
                    "status": "500",
                    "message": "Failed to upload image",
                    "messageKey": "image-upload-failure",
                    "details": "There was an error uploading your image. Please try again later.",
                    "type": "ImageUploadException",
                    "code": 500501,
                    "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/upload-image"  # Optional, include if relevant to your application
                }
            }
            return jsonify(error_response), 500

        finally:
            cursor.close()
            conn.close()


def hello():
    print("hello world!")

# error_response = {
#     "error": {
#         "status": "400",
#         "message": "Invalid or expired token",
#         "messageKey": "invalid-expired-token-txt",
#         "details": "The provided token is either invalid or has expired. Please request a new one.",
#         "type": "TokenException",
#         "code": 400402,
#         "timeStamp": dt.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
#         "instance": "/v1/auth/token"  # Optional, include if relevant to your application
#     }
# }
# return jsonify(error_response), 400

