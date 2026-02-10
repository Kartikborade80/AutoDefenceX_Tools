import sqlite3
import os

db_path = 'autodefencex_v2.db'

if not os.path.exists(db_path):
    print(f"Error: Database file {db_path} not found.")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print(f"Updating database for Phase 2: {db_path}")

try:
    # 1. Update User table
    print("Updating 'users' table...")
    columns_to_add = [
        ("must_change_password", "BOOLEAN DEFAULT 0"),
        ("password_changed_at", "DATETIME")
    ]
    for col, ty in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {ty}")
        except sqlite3.OperationalError as e: print(f"  Note: {e}")

    # 2. Update Attendance table
    print("Updating 'attendance' table...")
    columns_to_add = [
        ("browser_name", "TEXT"),
        ("browser_version", "TEXT"),
        ("os_name", "TEXT"),
        ("os_version", "TEXT")
    ]
    for col, ty in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE attendance ADD COLUMN {col} {ty}")
        except sqlite3.OperationalError as e: print(f"  Note: {e}")

    # 3. Create PasswordHistory table
    print("Creating 'password_history' table...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        hashed_password TEXT,
        created_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 4. Create SecurityAlert table
    print("Creating 'security_alerts' table...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        alert_type TEXT,
        severity TEXT,
        description TEXT,
        is_resolved BOOLEAN DEFAULT 0,
        timestamp DATETIME,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)
    
    conn.commit()
    print("✅ Phase 2 Database migration completed successfully.")

except Exception as e:
    print(f"❌ Error during migration: {e}")
    conn.rollback()
finally:
    conn.close()
