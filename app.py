from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
from flask import Flask, flash, render_template, session, request, redirect, url_for
import csv
import os
import json
from datetime import datetime
from slack_sdk.webhook import WebhookClient
import requests
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login', next=request.endpoint))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(email='admin@example.com', role='admin')
        admin.set_password('hello123')
        db.session.add(admin)
        db.session.commit()


CSV_FILE = 'devices.csv'
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"  # Replace with your actual webhook
webhook = WebhookClient(SLACK_WEBHOOK_URL)

def read_devices():
    devices = []
    if not os.path.exists(CSV_FILE):
        return devices
    try:
        with open(CSV_FILE, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                devices.append(row)
    except Exception as e:
        print("Error reading CSV:", e)
    return devices

def write_devices(devices):
    fieldnames = ['Sr No', 'Device Name','Serial Number', 'Status', 'Assigned To', 'Updated On', 'Location']
    try:
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(devices)
    except Exception as e:
        print("Error writing to CSV:", e)

def send_slack_message(message):
    try:
        response = webhook.send(text=message)
        if not response.status_code == 200:
            raise Exception(f"WebhookClient failed with {response.status_code}")
    except Exception:
        try:
            response = requests.post(SLACK_WEBHOOK_URL, json={'text': message})
            if response.status_code != 200:
                print(f"Slack webhook failed: {response.text}")
        except Exception as e:
            print("Slack notification failed:", e)

@app.route('/')
@login_required
def index():
    devices = read_devices()
    search_query = request.args.get('search', '').lower()
    if search_query:
        devices = [d for d in devices if search_query in d['Device Name'].lower() or search_query in d['Serial Number'].lower()]
    return render_template('index.html', devices=devices)

@app.route('/assign', methods=['POST'])
@login_required
def assign():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    devices = read_devices()
    device_name = request.form.get('device')
    user = request.form.get('user')
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for device in devices:
        if device.get('Device Name') == device_name:
            device['Status'] = 'In Use'
            device['Assigned To'] = user
            device['Updated On'] = now
            send_slack_message(f":iphone: *{user}* is now using *{device_name}* at {now}")
            break

    write_devices(devices)
    return redirect('/')

@app.route('/return', methods=['POST'])
@login_required
def return_device():
    devices = read_devices()
    device_name = request.form.get('device')
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for device in devices:
        if device.get('Device Name') == device_name:
            device['Status'] = 'Available'
            device['Assigned To'] = ''
            device['Updated On'] = now
            send_slack_message(f":white_check_mark: *{device_name}* has been returned and is now *available*.")
            break

    write_devices(devices)
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated and current_user.role != 'admin':
        flash("Only admins can create new users.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        new_user = User(email=email, role='user')  # Always default to 'user'
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/update_role/<int:user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    if user.email == 'admin@example.com':
        flash("You cannot change the role of the default admin.", "warning")
        return redirect(url_for('manage_users'))

    if new_role in ['user', 'admin']:
        user.role = new_role
        db.session.commit()
        flash(f"Updated {user.email}'s role to {new_role}.", "success")
    else:
        flash("Invalid role selected.", "danger")

    return redirect(url_for('manage_users'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
