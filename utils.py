from flask import Flask 
import secrets
from redis import Redis

class redis_config:
    redis_client=None
    def redis(cls):
        REDIS_HOST = 'localhost'
        REDIS_PORT = 6379
        REDIS_DB = 0
        redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        return redis_client 
    
    def app_object():
        app = Flask(__name__)
        return app
    
    def token_generation():
        return secrets.token_hex(16)