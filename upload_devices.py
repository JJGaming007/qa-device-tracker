import psycopg2
import csv
from datetime import datetime

conn = psycopg2.connect(
    dbname="neondb",  # or "neondb", based on your project
    user="neondb_owner",            # make sure this matches the username in Neon
    password="npg_w6CQ1VcxEkvI",  # ⚠️ replace with the actual password
    host="ep-restless-butterfly-a4a467o5-pooler.us-east-1.aws.neon.tech",
    port="5432",
    sslmode="require"
)
cur = conn.cursor()

with open('devices.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        updated_on = None
        if row['Updated On']:
            try:
                updated_on = datetime.strptime(row['Updated On'], "%d-%m-%Y %H:%M")
            except ValueError:
                updated_on = datetime.strptime(row['Updated On'], "%Y-%m-%d %H:%M:%S")
        cur.execute("""
            INSERT INTO devices (device_name, serial_number, status, assigned_to, updated_on, location)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            row['Device Name'],
            row['Serial Number'],
            row['Status'],
            row['Assigned To'],
            updated_on,
            row['Location']
        ))

conn.commit()
cur.close()
conn.close()
