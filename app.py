from flask import Flask, request ,jsonify
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
import jwt
import secrets
from functools import wraps
from redis import Redis
import random  
from database_renote import operations
from methods.method import all_methods
from utils import redis_config
import datetime;

all_methods_instance = all_methods()
utils_instance=redis_config()



app = Flask(__name__)
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
        print(request.headers)
        token = None
        if not request.headers.get('Authorization'):
            return jsonify({'message': 'Token is missing!'}), 401
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1] 
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            token_user = data['username']# You can adjust this according to your payload
            token_email=data['email']
            token_application_id=data['Application']
            token_client_id=data['Clientid']
            print(token_client_id)
            
            
            redis_username = redis_client.hget(token, 'username')
            
            if redis_username is None or redis_username.decode() != token_user or token_application_id != "renote" or token_client_id != "necun":
                print(token_client_id)
                return jsonify({'message': 'Token is invalid or expired!'}), 401
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(redis_username,token_user,token_email,token_application_id,token_client_id,token,*args, **kwargs)
 
    return decorated

def generate_unique_user_id():
    return random.randint(10**15, (10**16)-1)
 

@app.route('/user/signup', methods=['POST'])
def signup_main():
    method_response=all_methods_instance.signup()
    if method_response is not None:
        return method_response 
    return jsonify({'message':'User created successfully'}), 201
 
@app.route('/user/signin', methods=['POST'])
def signin_main():
    method_response=all_methods_instance.signin(app)
    if method_response is not None:
        return method_response
 
@app.route('/upload_image', methods=['POST'])
@token_required
def upload_image_main(redis_user,token_user, token_email, token_application_id, token_client_id, token):
    
    method_response=all_methods_instance.upload_image(token_user)
    if method_response is not None:
        return method_response
    
    
 
 
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(token_user,token_email,token_application_id,token_client_id,token):
    print(token_user)
    print(token_email)
    redis_username = redis_client.hget(token, 'username')
    print(redis_username) 
    return jsonify({'message': 'This is a protected route accessible only with a valid token.'})
 
 
@app.route('/user/forgot_password', methods=['POST'] )
def forgot_password_main():
    method_response=all_methods_instance.forgot_password()
    if method_response is not None:
        return method_response
    
 
@app.route('/reset_password/<token>')
def reset_password_main(token):
    method_response=all_methods_instance.reset_password(token)
    if method_response is not None:
        return method_response
    
    
@app.route('/update_password', methods=['POST'])
def update_password_main():
    method_response=all_methods_instance.update_password()
    if method_response is not None:
        return method_response

@app.route('/')
def welcome():
    current_datetime = datetime.datetime.now()

    # Convert datetime object to string with a specific format
    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")


    print("current time:-", formatted_datetime)

    return 'Welcome to renote.ai at : ' + formatted_datetime

if __name__ == '__main__':
    app.run(debug=True)          
