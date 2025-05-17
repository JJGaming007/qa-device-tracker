from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, DeviceInventory
from flask_migrate import Migrate
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from functools import wraps
from flask import abort
from flask import Flask, flash, render_template, session, request, redirect, url_for, jsonify, current_app
from dotenv import load_dotenv
from dateutil import parser
import pytz
import csv
import os
import json
from datetime import datetime, timezone
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import requests
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

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

with app.app_context():
    db.create_all()


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
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()

    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(email='admin@example.com', role='admin')
        admin.set_password('hello123')
        db.session.add(admin)
        db.session.commit()

    print("Device count:", DeviceInventory.query.count())

CSV_FILE = 'devices.csv'
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

def read_devices():
    devices = []
    if not os.path.exists(CSV_FILE):
        return devices

    with open(CSV_FILE, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            devices.append({
                'Sr No': row.get('Sr No', ''),
                'Device Name': row.get('Device Name', ''),
                'Serial Number': row.get('Serial Number', ''),
                'Assigned To': row.get('Assigned To', ''),
                'Status': row.get('Status', '')
            })
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

slack_token = os.environ.get("SLACK_BOT_TOKEN")
slack_channel = os.environ.get("SLACK_CHANNEL")
slack_client = WebClient(token=slack_token)

def send_slack_message(message, thread_ts=None):
    try:
        response = slack_client.chat_postMessage(
            channel=slack_channel,
            text=message,
            thread_ts=thread_ts
        )
        return response["ts"]  # Return thread timestamp
    except SlackApiError as e:
        print(f"Slack API Error: {e.response['error']}")
    except Exception as ex:
        print(f"Slack send failed: {ex}")
    return None


@app.route('/')
@login_required
def index():
    search_query = request.args.get('search', '').strip().lower()

    query = DeviceInventory.query

    if search_query:
        query = query.filter(
            db.or_(
                DeviceInventory.device_name.ilike(f'%{search_query}%'),
                DeviceInventory.serial_number.ilike(f'%{search_query}%')
            )
        )

    devices = query.order_by(
        db.case(
            (DeviceInventory.status == 'In Use', 0),
            else_=1
        ),
        DeviceInventory.sr_no.asc()
    ).all()

    return render_template('index.html', devices=devices)

@app.cli.command('import_csv')
def import_csv():
    import csv
    from datetime import datetime, timezone

    with open('devices.csv', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            device = DeviceInventory(
                sr_no=int(row['Sr No']),
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


@app.route('/assign_device', methods=['POST'])
@login_required
@role_required('admin')
def assign_device():
    try:
        sr_no = request.form.get("sr_no")
        assigned_to = request.form.get("assigned_to", "").strip()

        if not sr_no:
            flash("Missing device ID", "danger")
            return redirect(url_for("index"))

        device = db.session.get(DeviceInventory, sr_no)
        if not device:
            flash("Device not found", "danger")
            return redirect(url_for("index"))

        now = datetime.now(pytz.timezone("Asia/Kolkata"))

        if not assigned_to or assigned_to.lower() in ["none", "unassigned"]:
            device.assigned_to = ""
            device.status = "Available"
            if device.slack_ts:
                send_slack_message("Returned ✅", thread_ts=device.slack_ts)
        else:
            device.assigned_to = assigned_to
            device.status = "In Use"
            status_message = (
                f"📱 *{device.device_name}* (S/N: {device.serial_number}) has been *assigned* to *{assigned_to}* "
                f"by *{current_user.email}* at {now.strftime('%Y-%m-%d %H:%M:%S')} IST."
            )
            ts = send_slack_message(status_message)
            if ts:
                device.slack_ts = ts

        device.updated_on = now
        db.session.commit()

        flash("Device assignment updated successfully", "success")
        return redirect(url_for("index"))

    except Exception as e:
        print("Error in assign_device:", e)
        flash("An unexpected error occurred", "danger")
        return redirect(url_for("index"))

@app.route('/some-protected-route')
@login_required
def protected():
    if current_user.role != 'admin':
        flash('Contact your Admin', 'danger')
        return redirect(url_for('index'))
    return "You have accessed a protected admin route."

@app.route('/return_device', methods=['POST'])
@login_required
@role_required('admin')
def return_device():
    sr_no = request.form.get("sr_no")
    if not sr_no:
        flash("Missing sr_no", "danger")
        return redirect(url_for("index"))

    try:
        sr_no = int(sr_no)
    except ValueError:
        flash("Invalid device ID format", "danger")
        return redirect(url_for("index"))

    device = DeviceInventory.query.get(sr_no)
    if not device:
        flash("Invalid device ID", "danger")
        return redirect(url_for("index"))

    device.assigned_to = ""
    device.status = "Available"
    ist = pytz.timezone("Asia/Kolkata")
    device.updated_on = datetime.now(ist)

    # ✅ Reply to Slack thread if exists
    if device.slack_ts:
        send_slack_message("Returned ✅", thread_ts=device.slack_ts)
    else:
        send_slack_message(f"🔄 *{device.device_name}* (S/N: {device.serial_number}) was returned and is now available.")

    db.session.commit()
    flash("Device returned successfully", "success")
    return redirect(url_for("index"))

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
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
