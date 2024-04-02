from flask import redirect, url_for
from pymongo import MongoClient
import bcrypt
from auth.Security.security import generate_totp_uri
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, client, db, users_collection):
            self.client = client
            self.db = db
            self.collection = users_collection

    def create_user(self, username, email, password):
        otp_uri = generate_totp_uri(username)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'otp_uri': otp_uri,
            'is_otp_verified': False }
        self.collection.insert_one(user_data)

        print("-----------------------------------------------")
        print("User created successfully:")
        print("Username:", username)
        print("Email:", email)
        print("OTP URI:", otp_uri)
        print("-----------------------------------------------")

    def create_user_sso(self , username , email): 
        otp_uri = generate_totp_uri(username)
        
        user_data = {
            'username': username,
            'email': email,
            'otp_uri': otp_uri,
            'is_otp_verified': False
        }
        self.collection.insert_one(user_data)

        print("-----------------------------------------------")
        print("User created successfully for SAML:")
        print("Username:", username)
        print("Email:", email)
        print("OTP URI:", otp_uri)
        print(user_data)
        print("-----------------------------------------------")

    def verify_password(self, username, password):
        user = self.collection.find_one({'username': username})
        if user:
            stored_password = user.get('password')
            return bcrypt.checkpw(password.encode('utf-8'), stored_password)
        return False
    
    def get_user_by_username(self, username):
        return self.collection.find_one({'username': username})
    
    def get_email_by_username(self, username):
        return self.collection.find_one({'username': username}, {'email': 1})
    
    def get_user_by_email(self, email):
        return self.collection.find_one({'email': email})

    def get_otp_uri(self, username):
        return self.collection.find_one({'username': username}, {'otp_uri': 1})

    def set_totp_verification(self, username, is_verified):
        self.collection.update_one({'username': username}, {'$set': {'is_otp_verified': is_verified}})
    
    def get_all_users(self):
        return list(self.collection.find({}))
    
    def delete_user(self, username):
        self.collection.delete_one({'username': username})
    
    