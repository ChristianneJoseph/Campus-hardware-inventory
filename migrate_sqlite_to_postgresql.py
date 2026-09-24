import os
import sqlite3
import psycopg
from psycopg import sql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

SQLITE_DB = "hardware_inventory.db"
DATABASE_URL = os.getenv("DATABASE_URL")

# Table list with their primary key columns
TABLES = [
    ("system_users", "user_id"),
    ("password_resets", "request_id"),
    ("equipment_inventory", "asset_id"),
    ("lab_logbook", "log_id")
]

# PostgreSQL Table Creation DDL
CREATE_TABLES_SQL = [
    """
    CREATE TABLE IF NOT EXISTS system_users (
        user_id SERIAL PRIMARY KEY,
        account_username VARCHAR(100) UNIQUE NOT NULL,
        account_email VARCHAR(255) UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        user_role VARCHAR(20) NOT NULL DEFAULT 'USER',
        failed_login_count INT DEFAULT 0,
        is_locked INT DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS password_resets (
        request_id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        account_email VARCHAR(255) NOT NULL,
        new_hashed_password TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'PENDING',
        request_time DOUBLE PRECISION NOT NULL,
        FOREIGN KEY (user_id) REFERENCES system_users(user_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS equipment_inventory (
        asset_id SERIAL PRIMARY KEY,
        asset_name VARCHAR(255) UNIQUE NOT NULL,
        asset_category VARCHAR(100) NOT NULL,
        stock_qty INT NOT NULL,
        unit_val DOUBLE PRECISION NOT NULL,
        stock_status VARCHAR(50) NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS lab_logbook (
        log_id SERIAL PRIMARY KEY,
        borrower_name VARCHAR(100) NOT NULL,
        asset_id INT,
        asset_name VARCHAR(255) NOT NULL,
        qty_borrowed INT NOT NULL,
        checkout_time VARCHAR(50) NOT NULL,
        return_time VARCHAR(50) DEFAULT 'PENDING_BORROW',
        FOREIGN KEY (asset_id) REFERENCES equipment_inventory(asset_id)
    );
    """
]


def migrate():
    if not DATABASE_URL:
        print("Error: DATABASE_URL is not set.")
        return

    # 1. Connect to PostgreSQL and create schema directly
    print("Connecting to PostgreSQL (Supabase)...")
    pg_conn = psycopg.connect(DATABASE_URL)
    pg_cur = pg_conn.cursor()

    print("Creating tables in PostgreSQL...")
    for query in CREATE_TABLES_SQL:
        pg_cur.execute(query)
    pg_conn.commit()
    print("✓ Tables created successfully.\n")

    # 2. Connect to local SQLite database
    sqlite_conn = sqlite3.connect(SQLITE_DB)
    sqlite_cur = sqlite_conn.cursor()

    print("Starting data migration from SQLite to PostgreSQL...\n")

    for table_name, pk_column in TABLES:
        print(f"Processing table: '{table_name}'...")

        # Read from SQLite
        sqlite_cur.execute(f"SELECT * FROM {table_name}")
        rows = sqlite_cur.fetchall()

        if not rows:
            print(f"  └─ No rows found in SQLite '{table_name}'. Skipping.")
            continue

        col_names = [desc[0] for desc in sqlite_cur.description]

        # Construct PostgreSQL INSERT query
        insert_query = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO NOTHING").format(
            sql.Identifier(table_name),
            sql.SQL(", ").join(map(sql.Identifier, col_names)),
            sql.SQL(", ").join([sql.Placeholder()] * len(col_names))
        )

        pg_cur.executemany(insert_query, rows)
        pg_conn.commit()

        # Update PostgreSQL SERIAL sequence counter
        if pk_column:
            seq_fix_query = sql.SQL(
                "SELECT setval(pg_get_serial_sequence({}, {}), COALESCE(MAX({}), 1)) FROM {};"
            ).format(
                sql.Literal(table_name),
                sql.Literal(pk_column),
                sql.Identifier(pk_column),
                sql.Identifier(table_name)
            )
            pg_cur.execute(seq_fix_query)
            pg_conn.commit()

        print(f"  └─ Successfully migrated {len(rows)} row(s) into '{table_name}'.")

    sqlite_conn.close()
    pg_conn.close()
    print("\n✓ Migration completed successfully!")


if __name__ == "__main__":
    migrate()