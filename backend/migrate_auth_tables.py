import sys
import os
from sqlalchemy import create_engine, inspect

# Add current directory to path so we can import app modules
sys.path.append(os.getcwd())

from app.database import engine, Base
from app import models

def migrate_tables():
    print("Checking for missing tables...")
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    print(f"Existing tables: {existing_tables}")

    curr_metadata = Base.metadata
    
    tables_to_create = []
    for table_name, table in curr_metadata.tables.items():
        if table_name not in existing_tables:
            print(f"Table '{table_name}' is missing. Will create.")
            tables_to_create.append(table)
        else:
            print(f"Table '{table_name}' exists.")

    if tables_to_create:
        print("Creating missing tables...")
        Base.metadata.create_all(bind=engine)
        print("Migration complete!")
    else:
        print("All tables already exist.")

if __name__ == "__main__":
    migrate_tables()
