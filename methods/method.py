from flask import Flask, request, jsonify,render_template,json 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
import mysql.connector
from mysql.connector import pooling
from mysql.connector import Error as MySQLError
from mysql.connector import errorcode
import jwt
import datetime
import secrets
import os
from functools import wraps
from redis import Redis
import random
import re   

from database_renote.operations import db_methods  

db_instance = db_methods()

class all_methods:
    def hello(self):
        print("hellloo000000000 world")
        
    def generate_unique_user_id(self):
        return random.randint(10**15, (10**16)-1)
    
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
        profile_pic='NO_PIC'
    
        response=db_instance.signup_db_operation(application_id, client_id, user_id, username,  password, email , fullname, phone_number , profile_pic, 0)
        if response is not None:
            return response
        return jsonify({'message': 'User created successfully'}), 201
    
    def signin(self):
        data = request.json
   
        username = data['username']
        password = data['password']
        
        response=db_methods.signin_db_operation(username)
        if response is not None:
            return response
        
    def forgot_password(self):
        email = request.json.get('email')
        if not email:
            return jsonify({'message':'Email is required'}), 400
        
        response=db_methods.get_user_by_email(email)
        if response is not None:
            return response
    
    def reset_password_(self,token):
        response=db_methods.user_by_reset_token(token)
        if response is not None:
            return response
        
    def update_password(self):
        token=request.form.get('token')
        new_password=request.form.get('password')
        confirm_password=request.form.get('confirm_password')
 
        if new_password != confirm_password:
            return jsonify({'message':'passwords do not match'}), 400
        
        response=db_methods.db_method_update_password(token,new_password)
        if response is not None:
            return response