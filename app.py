from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, case, nullslast, text
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from models import db, User, DeviceInventory
from flask_migrate import Migrate
from flask_cors import CORS
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from functools import wraps
from flask import Flask, flash, render_template, request, redirect, url_for, jsonify
from dotenv import load_dotenv
from dateutil import parser
from flask_compress import Compress
import os, pytz, psycopg2, csv, threading
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
import asyncio
from concurrent.futures import ThreadPoolExecutor

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

print("DATABASE_URL:", os.environ.get("DATABASE_URL"))

app = Flask(__name__)  # ✅ Must come first
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
db_url = os.environ.get('DATABASE_URL')
if not db_url:
    raise RuntimeError("DATABASE_URL is not set in the environment.")
if "sslmode" not in db_url:
    url_parts = list(urlparse(db_url))
    query = parse_qs(url_parts[4])
    query["sslmode"] = "require"
    url_parts[4] = urlencode(query, doseq=True)
    db_url = urlunparse(url_parts)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,  # Increased from 10
    'max_overflow': 10,  # Increased from 5
    'pool_timeout': 10,  # Reduced from 30
    'pool_recycle': 1800,
    'pool_pre_ping': True,  # Added for connection health checks
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Optimized SocketIO configuration
socketio = SocketIO(app,
                    cors_allowed_origins="*",
                    async_mode='threading',  # Use threading for better performance
                    ping_timeout=60,
                    ping_interval=25)
CORS(app)
db.init_app(app)
migrate = Migrate(app, db)
Compress(app)

# Thread pool for async operations
executor = ThreadPoolExecutor(max_workers=10)


@app.cli.command("init-db")
def init_db():
    try:
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        print("✅ Database is connected and working.")
    except Exception as e:
        print("❌ Database connection failed:", e)
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
    from sqlalchemy import text

    try:
        db.session.execute(text('SELECT 1'))
        print("✅ Database connected.")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")

    if not User.query.filter_by(email='admin@supergaming.com').first():
        admin = User(email='admin@supergaming.com', role='admin')
        admin.set_password('testing123')
        db.session.add(admin)
        db.session.commit()

    print("Device count:", DeviceInventory.query.count())

CSV_FILE = 'devices.csv'


def write_devices(devices):
    fieldnames = ['Sr No', 'Device Name', 'Serial Number', 'Status', 'Assigned To', 'Updated On', 'Location']
    try:
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(devices)
    except Exception as e:
        print("Error writing to CSV:", e)


slack_token = os.environ.get("SLACK_API_TOKEN")
slack_channel = os.environ.get("SLACK_CHANNEL")
slack_client = WebClient(token=slack_token) if slack_token else None


def send_slack_message(message, thread_ts=None):
    """Non-blocking Slack message sending"""
    if not slack_client:
        return None

    def _send():
        try:
            response = slack_client.chat_postMessage(
                channel=slack_channel,
                text=message,
                thread_ts=thread_ts
            )
            return response["ts"]
        except SlackApiError as e:
            print(f"Slack API Error: {e.response['error']}")
        except Exception as ex:
            print(f"Slack send failed: {ex}")
        return None

    # Submit to thread pool and return immediately
    future = executor.submit(_send)
    return future


def send_slack_async(message, thread_ts=None):
    """Async Slack message sending - fire and forget"""
    if slack_client:
        executor.submit(send_slack_message, message, thread_ts)

def emit_device_update(device):
    """Optimized device update emission"""
    ist = pytz.timezone("Asia/Kolkata")
    device_data = {
        'sr_no': device.sr_no,
        'device_name': device.device_name,
        'status': device.status,
        'assigned_to': device.assigned_to or '',
        'updated_on': device.updated_on.astimezone(ist).isoformat() if device.updated_on else '',
        'location': device.location or ''
    }
    print(f"📡 Emitting device update: {device_data}")  # Debug log
    socketio.emit('device_updated', device_data, namespace='/')

@app.route('/bulk_operation', methods=['POST'])
@login_required
@role_required('admin')
def bulk_operation():
    try:
        data = request.get_json()
        operation = data.get('operation')
        device_ids = data.get('device_ids', [])
        assigned_to = data.get('assigned_to', '').strip()

        if not device_ids:
            return jsonify({'success': False, 'message': 'No devices selected'}), 400

        ist = pytz.timezone("Asia/Kolkata")
        now = datetime.now(ist)

        # Batch query all devices at once
        devices = db.session.query(DeviceInventory).filter(
            DeviceInventory.sr_no.in_([int(id) for id in device_ids if str(id).isdigit()])
        ).all()

        updated_devices = []
        slack_messages = []

        for device in devices:
            if operation == 'assign' and assigned_to:
                if not device.assigned_to:
                    device.assigned_to = assigned_to
                    device.status = "In Use"
                    device.updated_on = now
                    updated_devices.append(device)

                    # Prepare Slack message for async sending
                    slack_messages.append({
                        'message': f"📱 *Device:* {device.device_name}\n"
                                   f"*Serial Number:* {device.serial_number}\n"
                                   f"*Assigned to:* {assigned_to}\n"
                                   f"*Assigned by:* {current_user.email}\n",
                        'device': device
                    })

            elif operation == 'return':
                if device.assigned_to:
                    device.assigned_to = ""
                    device.status = "Available"
                    device.updated_on = now
                    updated_devices.append(device)

                    # Prepare Slack message for async sending
                    if device.slack_ts:
                        slack_messages.append({
                            'message': "Returned ✅ (Bulk Operation)",
                            'thread_ts': device.slack_ts
                        })
                    else:
                        slack_messages.append({
                            'message': f"🔄 *{device.device_name}* (S/N: {device.serial_number}) was returned and is now available (Bulk Operation)."
                        })

            elif operation == 'toggle_allocate':
                if device.assigned_to:
                    if device.status == "Allocated":
                        device.status = "In Use"
                        operation_word = "unallocated"
                        slack_msg = "🔓 Unallocated (Bulk Operation)"
                    else:
                        device.status = "Allocated"
                        operation_word = "allocated"
                        slack_msg = "🔒 Allocated - Permanent (Bulk Operation)"

                    device.updated_on = now
                    updated_devices.append(device)

                    if device.slack_ts:
                        slack_messages.append({
                            'message': slack_msg,
                            'thread_ts': device.slack_ts
                        })

        # Commit all changes at once
        if updated_devices:
            db.session.commit()

        # Send Slack messages asynchronously
        for msg_data in slack_messages:
            send_slack_async(msg_data['message'], msg_data.get('thread_ts'))

        # Emit socket events for all updated devices
        for device in updated_devices:
            emit_device_update(device)

        if operation == 'toggle_allocate':
            return jsonify({
                'success': True,
                'message': f'{len(updated_devices)} devices allocation status updated successfully'
            }), 200
        else:
            operation_word = "assigned" if operation == 'assign' else "returned"
            return jsonify({
                'success': True,
                'message': f'{len(updated_devices)} devices {operation_word} successfully'
            }), 200

    except Exception as e:
        print("Error in bulk_operation:", e)
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500


from sqlalchemy import or_, func


@app.route('/')
@login_required
def index():
    search_query = request.args.get('search', '').strip().lower()

    query = DeviceInventory.query

    if search_query:
        query = query.filter(
            or_(
                func.lower(DeviceInventory.device_name).ilike(f'%{search_query}%'),
                func.lower(DeviceInventory.serial_number).ilike(f'%{search_query}%'),
                func.lower(DeviceInventory.assigned_to).ilike(f'%{search_query}%'),
                func.lower(DeviceInventory.status).ilike(f'%{search_query}%'),
                func.lower(DeviceInventory.location).ilike(f'%{search_query}%'),
            )
        )

    # Optimized ordering
    devices = query.order_by(
        DeviceInventory.sr_no.asc(),
        case((func.lower(DeviceInventory.status) == "in use", 0), else_=1),
        nullslast(DeviceInventory.updated_on.desc()),
        nullslast(DeviceInventory.device_name.asc())
    ).all()

    return render_template('index.html', devices=devices, search_query=search_query)


@app.cli.command('import_csv')
def import_csv():
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
        if request.is_json:
            data = request.get_json()
            sr_no = data.get("sr_no")
            assigned_to = data.get("assigned_to", "").strip()
            search_param = data.get("search", "")
            return_json = True
        else:
            sr_no = request.form.get("sr_no")
            assigned_to = request.form.get("assigned_to", "").strip()
            search_param = request.form.get("search", "")
            return_json = False

        if not sr_no:
            if return_json:
                return jsonify({'success': False, 'message': 'Missing device ID'}), 400
            flash("Missing device ID", "danger")
            return redirect(url_for("index", search=search_param))

        device = db.session.get(DeviceInventory, sr_no)
        if not device:
            if return_json:
                return jsonify({'success': False, 'message': 'Device not found'}), 404
            flash("Device not found", "danger")
            return redirect(url_for("index", search=search_param))

        now = datetime.now(pytz.timezone("Asia/Kolkata"))

        # Update device first
        if not assigned_to or assigned_to.lower() in ["none", "unassigned"]:
            device.assigned_to = ""
            device.status = "Available"
            operation_type = "returned"
        else:
            device.assigned_to = assigned_to
            device.status = "In Use"
            operation_type = "assigned"

        device.updated_on = now

        # Commit changes first
        db.session.commit()

        # Emit socket update immediately after DB commit
        emit_device_update(device)

        # Send Slack messages asynchronously (non-blocking)
        if operation_type == "returned" and device.slack_ts:
            send_slack_async("Returned ✅", thread_ts=device.slack_ts)
        elif operation_type == "assigned":
            status_message = (
                f"*Device:* {device.device_name}\n"
                f"*Serial Number:* {device.serial_number}\n"
                f"*Assigned to:* {assigned_to}\n"
                f"*Assigned by:* {current_user.email}\n"
            )

            # Handle Slack timestamp update asynchronously
            def handle_slack():
                try:
                    response = send_slack_message(status_message)
                    if response:
                        ts = response.result(timeout=3)  # Wait for the result
                        if ts:
                            # Update the device with slack_ts in a new session
                            with app.app_context():
                                device_update = db.session.get(DeviceInventory, sr_no)
                                if device_update:
                                    device_update.slack_ts = ts
                                    db.session.commit()
                except Exception as e:
                    print(f"Slack handling error: {e}")

            executor.submit(handle_slack)

        if return_json:
            return jsonify({
                'success': True,
                'message': f'Device {operation_type} successfully',
                'device': {
                    'sr_no': device.sr_no,
                    'status': device.status,
                    'assigned_to': device.assigned_to
                }
            }), 200

        flash(f"Device {operation_type} successfully", "success")
        return redirect(url_for("index", search=search_param))

    except Exception as e:
        print("Error in assign_device:", e)
        db.session.rollback()
        if return_json:
            return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500
        flash("An unexpected error occurred", "danger")
        return redirect(url_for("index", search=search_param))


@app.route('/some-protected-route')
@login_required
def protected():
    if current_user.role != 'admin':
        flash('Contact your Admin', 'danger')
        return redirect(url_for('index'))
    return "You have accessed a protected admin route."

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {'status': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")


@app.route('/return_device', methods=['POST'])
@login_required
@role_required('admin')
def return_device():
    try:
        if request.is_json:
            data = request.get_json()
            sr_no = data.get("sr_no")
            search_param = data.get("search", "")
            return_json = True
        else:
            sr_no = request.form.get("sr_no")
            search_param = request.form.get("search", "")
            return_json = False

        if not sr_no:
            if return_json:
                return jsonify({'success': False, 'message': 'Missing sr_no'}), 400
            flash("Missing sr_no", "danger")
            return redirect(url_for("index", search=search_param))

        try:
            sr_no = int(sr_no)
        except ValueError:
            if return_json:
                return jsonify({'success': False, 'message': 'Invalid device ID format'}), 400
            flash("Invalid device ID format", "danger")
            return redirect(url_for("index", search=search_param))

        device = db.session.get(DeviceInventory, sr_no)
        if not device:
            if return_json:
                return jsonify({'success': False, 'message': 'Invalid device ID'}), 404
            flash("Invalid device ID", "danger")
            return redirect(url_for("index", search=search_param))

        # Store slack_ts before updating
        stored_slack_ts = device.slack_ts

        # Update device first
        device.assigned_to = ""
        device.status = "Available"
        ist = pytz.timezone("Asia/Kolkata")
        device.updated_on = datetime.now(ist)

        # Commit changes first
        db.session.commit()

        # Emit socket update immediately after DB commit
        emit_device_update(device)

        # Send Slack messages asynchronously (non-blocking)
        if stored_slack_ts:
            send_slack_async("Returned ✅", thread_ts=stored_slack_ts)
        else:
            send_slack_async(
                f"🔄 *{device.device_name}* (S/N: {device.serial_number}) was returned and is now available.")

        if return_json:
            return jsonify({
                'success': True,
                'message': 'Device returned successfully',
                'device': {
                    'sr_no': device.sr_no,
                    'status': device.status,
                    'assigned_to': ''
                }
            }), 200

        flash("Device returned successfully", "success")
        return redirect(url_for("index", search=search_param))

    except Exception as e:
        print("Error in return_device:", e)
        db.session.rollback()
        if return_json:
            return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500
        flash("An unexpected error occurred", "danger")
        return redirect(url_for("index", search=search_param))


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

        new_user = User(email=email, role='user')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/allocate_device', methods=['POST'])
@login_required
@role_required('admin')
def allocate_device():
    try:
        data = request.get_json()
        sr_no = data.get("sr_no")
        allocate = data.get("allocate", True)
        search_param = data.get("search", "")

        if not sr_no:
            return jsonify({'success': False, 'message': 'Missing device ID'}), 400

        device = db.session.get(DeviceInventory, sr_no)
        if not device:
            return jsonify({'success': False, 'message': 'Device not found'}), 404

        if not device.assigned_to:
            return jsonify({'success': False, 'message': 'Cannot allocate unassigned device'}), 400

        now = datetime.now(pytz.timezone("Asia/Kolkata"))

        # Toggle allocation status
        if allocate:
            device.status = "Allocated"
            operation_type = "allocated"
        else:
            device.status = "In Use"
            operation_type = "unallocated"

        device.updated_on = now
        db.session.commit()

        # Emit socket update
        emit_device_update(device)

        # Send Slack notification
        if device.slack_ts:
            status_message = f"{'🔒 Allocated (Permanent)' if allocate else '🔓 Unallocated'}"
            send_slack_async(status_message, thread_ts=device.slack_ts)

        return jsonify({
            'success': True,
            'message': f'Device {operation_type} successfully',
            'device': {
                'sr_no': device.sr_no,
                'status': device.status,
                'assigned_to': device.assigned_to
            }
        }), 200

    except Exception as e:
        print("Error in allocate_device:", e)
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500


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


@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)


# Keep the old route for backward compatibility
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_users():
    return redirect(url_for('manage_users'))


@app.route('/admin/update_role/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    if user.email == 'admin@supergaming.com':
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


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({'message': 'Login successful', 'role': user.role}), 200
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/devices', methods=['GET'])
@login_required
def api_devices():
    devices = DeviceInventory.query.all()
    ist = pytz.timezone("Asia/Kolkata")
    return jsonify([
        {
            'sr_no': d.sr_no,
            'device_name': d.device_name,
            'serial_number': d.serial_number,
            'status': d.status,
            'assigned_to': d.assigned_to,
            'updated_on': d.updated_on.astimezone(ist).isoformat() if d.updated_on else None,  # Convert to IST
            'location': d.location
        } for d in devices
    ])

@app.route('/api/assign_device', methods=['POST'])
@login_required
def api_assign_device():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    sr_no = data.get('sr_no')
    assigned_to = data.get('assigned_to')
    location = data.get('location')

    device = DeviceInventory.query.get(sr_no)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    device.status = 'Assigned'
    device.assigned_to = assigned_to
    device.updated_on = datetime.now()
    device.location = location
    db.session.commit()
    return jsonify({'message': 'Device assigned successfully'}), 200


@app.route('/api/return_device', methods=['POST'])
@login_required
def api_return_device():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    sr_no = data.get('sr_no')
    device = DeviceInventory.query.get(sr_no)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    device.status = 'Available'
    device.assigned_to = None
    device.updated_on = datetime.now()
    device.location = None
    db.session.commit()
    return jsonify({'message': 'Device returned successfully'}), 200


if __name__ == '__main__':
    import os

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)