from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    status = db.Column(db.String(50))
    assigned_to = db.Column(db.String(100))
    updated_on = db.Column(db.DateTime)
    location = db.Column(db.String(100))

