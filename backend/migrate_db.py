"""
Database Migration Script
Adds new session tracking columns to attendance table
"""
from app.database import Base, engine
from sqlalchemy import inspect, text

print("🔄 Starting database migration...")

# Check current columns
inspector = inspect(engine)
current_columns = [col['name'] for col in inspector.get_columns('attendance')]
print(f"Current columns: {current_columns}")

# Check if migration is needed
new_columns = ['session_token', 'last_activity', 'is_active', 'logout_reason']
needs_migration = not all(col in current_columns for col in new_columns)

if needs_migration:
    print("⚠️  Migration needed - adding new columns...")
    
    with engine.connect() as conn:
        # Add new columns if they don't exist
        if 'session_token' not in current_columns:
            conn.execute(text('ALTER TABLE attendance ADD COLUMN session_token VARCHAR'))
            conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ix_attendance_session_token ON attendance(session_token)'))
            print("✅ Added session_token column")
        
        if 'last_activity' not in current_columns:
            conn.execute(text('ALTER TABLE attendance ADD COLUMN last_activity DATETIME'))
            print("✅ Added last_activity column")
        
        if 'is_active' not in current_columns:
            conn.execute(text('ALTER TABLE attendance ADD COLUMN is_active BOOLEAN DEFAULT 1'))
            print("✅ Added is_active column")
        
        if 'logout_reason' not in current_columns:
            conn.execute(text('ALTER TABLE attendance ADD COLUMN logout_reason VARCHAR'))
            print("✅ Added logout_reason column")
        
        conn.commit()
    
    print("✅ Migration completed successfully!")
else:
    print("✅ Database already up to date - no migration needed")

# Verify final schema
inspector = inspect(engine)
final_columns = [col['name'] for col in inspector.get_columns('attendance')]
print(f"\nFinal attendance columns: {final_columns}")
