from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Device
from flask_migrate import Migrate
from functools import wraps
from flask import abort
from flask import Flask, flash, render_template, session, request, redirect, url_for
from dotenv import load_dotenv
from dateutil import parser
import csv
import os
import json
from datetime import datetime
from slack_sdk.webhook import WebhookClient
import requests
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

print("DATABASE_URL:", os.environ.get("DATABASE_URL"))

app = Flask(__name__)  # ✅ Must come first
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
db_url = os.environ.get('DATABASE_URL')
if not db_url:
    raise RuntimeError("DATABASE_URL is not set in the environment.")
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

from models import *

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('Access denied.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


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

    print("Device count:", Device.query.count())

CSV_FILE = 'devices.csv'
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"  # Replace with your actual webhook
webhook = WebhookClient(SLACK_WEBHOOK_URL)

def read_devices():
    print("📥 read_devices() was called")
    devices = []
    if not os.path.exists(CSV_FILE):
        return devices

    with open(CSV_FILE, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print("CSV Row Keys:", list(row.keys()))
            device = {
                'Sr No': row.get('Sr No', ''),
                'Device Name': row.get('Device Name', ''),
                'Serial Number': row.get('Serial Number', ''),
                'Assigned To': row.get('Assigned To', ''),
                'Status': row.get('Status', ''),
            }
            devices.append(device)
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
    search_query = request.args.get('search', '').lower()
    devices = Device.query.all()

    if search_query:
        devices = [d for d in devices if search_query in d.device_name.lower() or search_query in d.serial_number.lower()]

    # Sort: 'In Use' devices first
    devices.sort(key=lambda x: 0 if x.status == 'In Use' else 1)

    return render_template('index.html', devices=devices)

    with app.app_context():
        print("Device count:", Device.query.count())

@app.cli.command('import_csv')
def import_csv():
    import csv
    from datetime import datetime

    with open('devices.csv', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            device = Device(
                device_name=row['Device Name'],
                serial_number=row['Serial Number'],
                status=row['Status'],
                assigned_to=row['Assigned To'],
                updated_on=parser.parse(row['Updated On']) if row['Updated On'] else None,
                location=row['Location']
            )
            db.session.add(device)
        db.session.commit()
        print("Imported devices from CSV.")


@app.route('/assign', methods=['POST'])
@login_required
@role_required('admin')
def assign():
    device_name = request.form.get('device')
    user = request.form.get('user')
    now = datetime.now()

    device = Device.query.filter_by(device_name=device_name).first()
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('index'))

    device.status = 'In Use'
    device.assigned_to = user
    device.updated_on = now
    db.session.commit()

    send_slack_message(f":iphone: *{user}* is now using *{device_name}* at {now.strftime('%Y-%m-%d %H:%M:%S')}")
    flash(f"{device_name} assigned to {user}.", "success")

    return redirect(url_for('index'))

@app.route('/some-protected-route')
@login_required
def protected():
    if current_user.role != 'admin':
        flash('Contact your Admin', 'danger')
        return redirect(url_for('index'))
    return "You have accessed a protected admin route."

@app.route('/return', methods=['POST'])
@login_required
def return_device():
    device_name = request.form.get('device')
    now = datetime.now()

    device = Device.query.filter_by(device_name=device_name).first()
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('index'))

    device.status = 'Available'
    device.assigned_to = ''
    device.updated_on = now
    db.session.commit()

    send_slack_message(f":white_check_mark: *{device_name}* has been returned and is now *available*.")
    flash(f"{device_name} returned successfully.", "success")

    return redirect(url_for('index'))

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
    print("🔍 Testing read_devices() output:")
    for d in read_devices():
        print(d)

print("🔧 Manual CSV check:")
_ = read_devices()

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
