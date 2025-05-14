from flask import Flask, render_template, request, redirect
import csv
import os
from datetime import datetime
from slack_sdk.webhook import WebhookClient
import requests

app = Flask(__name__)

CSV_FILE = 'devices.csv'
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"  # Replace with your actual webhook
webhook = WebhookClient(SLACK_WEBHOOK_URL)


def read_devices():
    devices = []
    if not os.path.exists(CSV_FILE):
        print(f"CSV file '{CSV_FILE}' not found. Returning empty list.")
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
        # Fallback to raw HTTP if Slack SDK fails
        try:
            response = requests.post(SLACK_WEBHOOK_URL, json={'text': message})
            if response.status_code != 200:
                print(f"Slack webhook failed: {response.text}")
        except Exception as e:
            print("Slack notification failed:", e)


@app.route('/')
def index():
    devices = read_devices()
    search_query = request.args.get('search', '').lower()

    if search_query:
        devices = [d for d in devices if search_query in d['Device Name'].lower() or search_query in d['Serial Number'].lower()]

    return render_template('index.html', devices=devices)


@app.route('/assign', methods=['POST'])
def assign():
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


if __name__ == '__main__':
    app.run(debug=True)
