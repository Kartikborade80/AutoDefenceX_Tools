import sqlite3
import os

db_path = 'autodefencex_v2.db'

if not os.path.exists(db_path):
    print(f"Error: Database file {db_path} not found.")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print(f"Updating database: {db_path}")

try:
    # 1. Update User table
    print("Updating 'users' table...")
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
    except sqlite3.OperationalError as e: print(f"  Note: {e}")
    
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN account_locked_until DATETIME")
    except sqlite3.OperationalError as e: print(f"  Note: {e}")
    
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN last_failed_login DATETIME")
    except sqlite3.OperationalError as e: print(f"  Note: {e}")

    # 2. Update Attendance table
    print("Updating 'attendance' table...")
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN ip_address TEXT")
    except sqlite3.OperationalError as e: print(f"  Note: {e}")
    
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN user_agent TEXT")
    except sqlite3.OperationalError as e: print(f"  Note: {e}")
    
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN device_fingerprint TEXT")
    except sqlite3.OperationalError as e: print(f"  Note: {e}")

    # 3. Create LoginAttempt table
    print("Creating 'login_attempts' table...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip_address TEXT,
        success BOOLEAN,
        timestamp DATETIME,
        user_agent TEXT,
        failure_reason TEXT
    )
    """)
    
    conn.commit()
    print("✅ Database migration completed successfully.")

except Exception as e:
    print(f"❌ Error during migration: {e}")
    conn.rollback()
finally:
    conn.close()
