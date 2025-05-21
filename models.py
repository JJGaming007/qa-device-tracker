from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(64), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class DeviceInventory(db.Model):
    __tablename__ = 'device_inventory'

    sr_no = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(255))
    serial_number = db.Column(db.String(255))
    status = db.Column(db.String(50))
    assigned_to = db.Column(db.String(255))
    updated_on = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    location = db.Column(db.String(255))
    slack_ts = db.Column(db.String(255))