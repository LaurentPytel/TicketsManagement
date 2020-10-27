

import uuid 
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import UserMixin, LoginManager
from flask import session
from ApplicationFlask import app, database

app.config['SECRET_KEY'] = 'ma session est tres tres secrete'

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user =User.get_by_id(user_id)
    if user is not None:
        return user
    else:
        return None

class User(UserMixin):
    
    def __init__(self, username, email, password, _id=None):

        self.username = username
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def is_authenticated(self):
        return True
    def is_active(self):
        return True
    def is_anonymous(self):
        return False
    def get_id(self):
        return self._id

    @classmethod
    def get_by_username(cls, username):
        data = database.Users.find_one({"username": username})
        if data is not None:
           return cls(**data)

    @classmethod
    def get_by_email(cls, email):
        data = database.Users.find_one({"email": email})
        if data is not None:
            return cls(**data)

    @classmethod
    def get_by_id(cls, _id):
        data = database.Users.find_one({"_id": _id})
        if data is not None:
            return cls(**data)

    @staticmethod
    def login_valid(user, password):
        if user is not None:
            return check_password_hash(user.password, password)
        return False

    @classmethod
    def register(cls, username, email, password):
        user = cls.get_by_email(email)
        if user is None:
            encryptedPassword = generate_password_hash(password, method='sha256')
            new_user = cls( username, email, encryptedPassword)
            new_user.save_to_mongo()
            session['email'] = email
            return True
        else:
            return False

    def json(self):
        return {
            "username": self.username,
            "email": self.email,
            "_id": self._id,
            "password": self.password
        }

    def save_to_mongo(self):
        database.Users.insert(self.json())
