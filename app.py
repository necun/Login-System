from flask import Flask, request ,jsonify,redirect , url_for
from loggers.logger import logger_instance
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
import jwt
import os
import secrets
from functools import wraps
from redis import Redis
import random
from database_renote import operations
from methods.method import all_methods
from utils import redis_config
import datetime
from flask_mail import Mail , Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
# import logging



all_methods_instance = all_methods()
utils_instance=redis_config()
# loggerObj= Logger()
# logger=loggerObj.getLogger()





# logger = logging.getLogger("my_logger")
# logger.setLevel(logging.INFO)
# log_formatter  = logging.Formatter("%(asctime)s,%(levelname)s,%(message)s")
# file_handler = TimedRotatingFileHandler("renote_logins_logs", when='midnight', interval=1, backupCount=90)

# file_handler.setFormatter(log_formatter)
# file_handler.setLevel(logging.ERROR)
# logger.addHandler(file_handler)


app = Flask(__name__)

app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '114aa8c148a466'#os.environ.get('EMAIL_USERNAME')
app.config['MAIL_PASSWORD'] = '1adda0aa9304a8'#os.environ.get('EMAIL_password')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail=Mail(app)

secret_key = secrets.token_hex(16)
app.config['SECRET_KEY'] = secret_key



REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)


# Azure Blob Storage Configuration
AZURE_STORAGE_CONNECTION_STRING = 'DefaultEndpointsProtocol=https;AccountName=necunblobstorage;AccountKey=hgzRK0zpgs+bXf4wnfvFLEJNbSMlbTNeJBuhYHS9jcTrRTzlh0lVlT7K59U8yG0Ojh65p/c4sV97+AStOXtFWw==;EndpointSuffix=core.windows.net'
CONTAINER_NAME = 'pictures'
print("Connection String:", AZURE_STORAGE_CONNECTION_STRING)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        logger_instance.info("Checking authorization token...")
        token = None
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
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Authorization header missing")
            return jsonify(error_response), 401
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
            logger_instance.info("Authorization header is present")
        if not token:
            error_response = {
                "error": {
                    "status": "401",
                    "message": "Token is missing",
                    "messageKey": "token-missing",
                    "details": "The request did not include a token or included an invalid token.",
                    "type": "AuthenticationException",
                    "code": 401405,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("Token is not provided")
            return jsonify(error_response), 401
        try:
            logger_instance.info("Required token is passed ")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            token_user = data['username']# You can adjust this according to your payload
            token_email=data['email']
            token_application_id=data['Application']
            token_client_id=data['Clientid']
            #logging(token_client_id)
            
            
            redis_username = redis_client.hget(token, 'username')
            
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
                            "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                            "instance": "/v1/"  # Optional, include if relevant to your application
                        }
                    }
                    return jsonify(error_response), 401
        except:
            error_response ={
                "error": {
                    "status": "401",
                    "message": "Token is invalid!",
                    "messageKey": "token-invalid",
                    "details": "The token is invalid or has expired.",
                    "type": "AuthenticationException",
                    "code": 400405,
                    "timeStamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S +0000'),
                    "instance": "/v1/"  # Optional, include if relevant to your application
                }
            }
            logger_instance.error("token is invalid")
            return jsonify(error_response), 401
        return f(redis_username,token_user,token_email,token_application_id,token_client_id,token,*args, **kwargs)

    return decorated

def generate_unique_user_id():
    return random.randint(10**15, (10**16)-1)


@app.route('/users/signUp', methods=['POST'])
def signup_main():
    logger_instance.info("Received sign-up request")
    method_response=all_methods_instance.signup()
    if method_response is not None:
        return method_response
    #return jsonify({'message':'User created successfully'}), 201

@app.route('/users/signIn', methods=['POST'])
def signin_main():
    logger_instance.info("Received sign-in request")
    method_response=all_methods_instance.signin(app)
    if method_response is not None:
        return method_response

@app.route('/uploadImages', methods=['POST'])
@token_required
def upload_image_main(redis_user,token_user, token_email, token_application_id, token_client_id, token):
    logger_instance.info("Received image upload request")
    method_response=all_methods_instance.upload_image(token_user)
    if method_response is not None:
        return method_response
    
    

@app.route('/protected', methods=['GET'])
@token_required
def protected_route(token_user,token_email,token_application_id,token_client_id,token):
    # logging(token_user)
    # logging(token_email)
    redis_username = redis_client.hget(token, 'username')
    # logging(redis_username)
    return jsonify({'message': 'This is a protected route accessible only with a valid token.'})

@app.route('/users/forgotPassword', methods=['POST'] )
def forgot_password_main():
    logger_instance.info("Received forgot password request")
    method_response=all_methods_instance.forgot_password()
    if method_response is not None:
        return method_response
    return redirect(url_for('reset_password_main'))
    
    

@app.route('/users/resetPassword/<token>')
def reset_password_main(token):
    logger_instance.info("Received reset password request")
    method_response=all_methods_instance.reset_password(token)
    if method_response is not None:
        return method_response
    
    
@app.route('/users/updatePassword', methods=['POST'])
def update_password_main():
    logger_instance.info("Received update password request")
    method_response=all_methods_instance.update_password()
    if method_response is not None:
        return method_response

@app.route('/')
def welcome():
    current_datetime = datetime.datetime.now()

    # Convert datetime object to string with a specific format
    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")


    #logging("current time:-", formatted_datetime)

    return 'Welcome to renote.ai at : ' + formatted_datetime

# @app.route('/send_email')
# def send_email():
#     msg = Message('Hello from Flask-Mail',
#                   sender='sainikhilch@renote.ai',
#                   recipients=['nikhilgriner23@gmail.com'])
#     msg.body = "This is a test email sent from Flask-Mail!"
#     mail.send(msg)
#     return jsonify({'message':'Email sent successfully!'}), 200


@app.route("/send-email", methods=["POST"])
def send_email():
    logger_instance.info("Received send email request")
    try:
        to_email = request.form['to_email']
        subject = request.form.get('subject', 'Your Doc is Ready - Renote.ai')
        message = request.form.get('message', 'Please check attached Doc.')

        msg = MIMEMultipart()
        msg['From'] = 'noreply.renote.ai@gmail.com'
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'html')) 

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('noreply.renote.ai@gmail.com', 'ihde zzml kkip opng')
            server.sendmail('noreply.renote.ai@gmail.com', to_email, msg.as_string())

        return jsonify({"message": f"Email sent successfully to {to_email}"})
    except Exception as e:
        logger_instance.error(f"Error sending email: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/hey')
def welcomeMessage():
    return jsonify({'message':'Welcome at Renote'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
