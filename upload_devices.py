import psycopg2
import csv
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Database connection
conn = psycopg2.connect(
    dbname="neondb",
    user="neondb_owner",
    password=os.getenv("DB_PASSWORD"),
    host="ep-restless-butterfly-a4a467o5-pooler.us-east-1.aws.neon.tech",
    port="5432",
    sslmode="require"
)

cur = conn.cursor()

# First, create the table if it doesn't exist
cur.execute("""
    CREATE TABLE IF NOT EXISTS device_inventory (
        sr_no SERIAL PRIMARY KEY,
        device_name VARCHAR(255) NOT NULL,
        serial_number VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'Available',
        assigned_to VARCHAR(255),
        updated_on TIMESTAMP,
        location VARCHAR(255),
        slack_ts VARCHAR(255)
    );
""")

# Clear existing data (optional - remove if you want to keep existing data)
# cur.execute("DELETE FROM device_inventory;")

# Import data from CSV
with open('devices.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    imported_count = 0
    skipped_count = 0

    for row in reader:
        try:
            # Handle date parsing with multiple formats
            updated_on = None
            if row.get('Updated On') and row['Updated On'].strip():
                date_str = row['Updated On'].strip()
                try:
                    # Try DD-MM-YYYY HH:MM format first
                    updated_on = datetime.strptime(date_str, "%d-%m-%Y %H:%M")
                except ValueError:
                    try:
                        # Try YYYY-MM-DD HH:MM:SS format
                        updated_on = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        try:
                            # Try DD/MM/YYYY HH:MM format
                            updated_on = datetime.strptime(date_str, "%d/%m/%Y %H:%M")
                        except ValueError:
                            try:
                                # Try YYYY-MM-DD format
                                updated_on = datetime.strptime(date_str, "%Y-%m-%d")
                            except ValueError:
                                print(f"Could not parse date: {date_str}")
                                updated_on = None

            # Insert or update device
            cur.execute("""
                INSERT INTO device_inventory (device_name, serial_number, status, assigned_to, updated_on, location)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (serial_number) 
                DO UPDATE SET 
                    device_name = EXCLUDED.device_name,
                    status = EXCLUDED.status,
                    assigned_to = EXCLUDED.assigned_to,
                    updated_on = EXCLUDED.updated_on,
                    location = EXCLUDED.location
            """, (
                row.get('Device Name', '').strip(),
                row.get('Serial Number', '').strip(),
                row.get('Status', 'Available').strip(),
                row.get('Assigned To', '').strip() if row.get('Assigned To', '').strip() else None,
                updated_on,
                row.get('Location', '').strip() if row.get('Location', '').strip() else None
            ))

            imported_count += 1

        except Exception as e:
            print(f"Error importing row {row}: {e}")
            skipped_count += 1
            continue

# Commit changes
conn.commit()

# Verify import
cur.execute("SELECT COUNT(*) FROM device_inventory;")
total_count = cur.fetchone()[0]

print(f"\n✅ Import completed!")
print(f"📊 Total devices in database: {total_count}")
print(f"✅ Successfully imported: {imported_count}")
print(f"❌ Skipped due to errors: {skipped_count}")

# Show sample data
cur.execute("SELECT sr_no, device_name, serial_number, status, assigned_to FROM device_inventory LIMIT 5;")
sample_data = cur.fetchall()

print(f"\n📋 Sample data:")
for row in sample_data:
    print(f"  {row[0]}: {row[1]} ({row[2]}) - {row[3]} - {row[4] or 'Unassigned'}")

# Close connections
cur.close()
conn.close()

print(f"\n🔒 Database connection closed.")