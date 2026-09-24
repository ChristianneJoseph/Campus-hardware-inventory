import csv
import os
import re
import sqlite3
import time
import bcrypt
from dotenv import load_dotenv

# Optional PostgreSQL driver support
try:
    import psycopg
except ImportError:
    psycopg = None

# Load environment variables from .env file
load_dotenv()

DATABASE_FILE = "hardware_inventory.db"


def get_db_connection():
    """
    Returns an active database connection and the parameter placeholder syntax
    (%s for PostgreSQL, ? for SQLite).
    """
    db_url = os.getenv("DATABASE_URL")
    if db_url and psycopg:
        conn = psycopg.connect(db_url)
        return conn, "%s"
    else:
        conn = sqlite3.connect(DATABASE_FILE)
        return conn, "?"


def setup_database_tables():
    """Dynamically creates tables and seeds default admin based on active database engine."""
    conn, p = get_db_connection()
    try:
        cursor = conn.cursor()
        is_postgres = (p == "%s")

        if is_postgres:
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_users (
                user_id SERIAL PRIMARY KEY,
                account_username VARCHAR(100) UNIQUE NOT NULL,
                account_email VARCHAR(255) UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                user_role VARCHAR(20) NOT NULL DEFAULT 'USER',
                failed_login_count INT DEFAULT 0,
                is_locked INT DEFAULT 0
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                request_id SERIAL PRIMARY KEY,
                user_id INT NOT NULL,
                account_email VARCHAR(255) NOT NULL,
                new_hashed_password TEXT NOT NULL,
                status VARCHAR(20) DEFAULT 'PENDING',
                request_time DOUBLE PRECISION NOT NULL,
                FOREIGN KEY (user_id) REFERENCES system_users(user_id)
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS equipment_inventory (
                asset_id SERIAL PRIMARY KEY,
                asset_name VARCHAR(255) UNIQUE NOT NULL,
                asset_category VARCHAR(100) NOT NULL,
                stock_qty INT NOT NULL,
                unit_val DOUBLE PRECISION NOT NULL,
                stock_status VARCHAR(50) NOT NULL
            );
            """)
            cursor.execute("""
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
            """)
        else:
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_username TEXT UNIQUE NOT NULL,
                account_email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                user_role TEXT NOT NULL DEFAULT 'USER',
                failed_login_count INTEGER DEFAULT 0,
                is_locked INTEGER DEFAULT 0
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_email TEXT NOT NULL,
                new_hashed_password TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                request_time REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES system_users(user_id)
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS equipment_inventory (
                asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_name TEXT UNIQUE NOT NULL,
                asset_category TEXT NOT NULL,
                stock_qty INTEGER NOT NULL,
                unit_val REAL NOT NULL,
                stock_status TEXT NOT NULL
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS lab_logbook (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                borrower_name TEXT NOT NULL,
                asset_id INTEGER,
                asset_name TEXT NOT NULL,
                qty_borrowed INTEGER NOT NULL,
                checkout_time TEXT NOT NULL,
                return_time TEXT DEFAULT 'PENDING_BORROW',
                FOREIGN KEY (asset_id) REFERENCES equipment_inventory(asset_id)
            )
            """)

        # Seed initial admin user if not existing
        cursor.execute(f"SELECT * FROM system_users WHERE user_role = {p}", ("ADMIN",))
        if not cursor.fetchone():
            default_admin_pass = bcrypt.hashpw("Admin@123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            cursor.execute(
                f"INSERT INTO system_users (account_username, account_email, hashed_password, user_role) VALUES ({p}, {p}, {p}, {p})",
                ("admin", "admin@system.com", default_admin_pass, "ADMIN")
            )
        conn.commit()
    except Exception as e:
        print(f"Database setup notice: {e}")
    finally:
        conn.close()


def init_db():
    setup_database_tables()


class AuthController:
    @staticmethod
    def login_user(username, password):
        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT user_id, hashed_password, user_role, failed_login_count, is_locked, account_email FROM system_users WHERE account_username={p}",
                (username,)
            )
            record = cursor.fetchone()
            if not record:
                return False, "Invalid username or password.", "USER", False, ""

            u_id, pw_hash, role, failed_count, is_locked, email = record
            if is_locked == 1:
                return False, "Your account is locked. Please request a password reset.", role, True, email

            if bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8")):
                cursor.execute(f"UPDATE system_users SET failed_login_count = 0 WHERE user_id={p}", (u_id,))
                conn.commit()
                return True, "Login successful!", role, False, email
            else:
                failed_count += 1
                lock_flag = 1 if failed_count >= 3 else 0
                cursor.execute(
                    f"UPDATE system_users SET failed_login_count = {p}, is_locked = {p} WHERE user_id={p}",
                    (failed_count, lock_flag, u_id)
                )
                conn.commit()
                msg = "Account locked due to 3 failed attempts." if lock_flag else "Invalid username or password."
                return False, msg, role, (lock_flag == 1), email
        finally:
            conn.close()

    @staticmethod
    def register_user(username, email, password, role="USER"):
        if not re.match("^[a-zA-Z0-9_]{3,20}$", username):
            return False, "Username must be 3-20 alphanumeric characters."
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False, "Invalid email address."
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"\d", password) or not re.search(r"[@#$%^&*]", password):
            return False, "Password requirements: >=8 chars, 1 uppercase, 1 digit, 1 special character."

        enc_p = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"INSERT INTO system_users (account_username, account_email, hashed_password, user_role) VALUES ({p}, {p}, {p}, {p})",
                (username, email, enc_p, role)
            )
            conn.commit()
            return True, "Account created successfully."
        except Exception:
            return False, "Username or Email already registered."
        finally:
            conn.close()

    @staticmethod
    def submit_password_reset_request(username, email, new_password):
        if len(new_password) < 8 or not re.search(r"[A-Z]", new_password) or not re.search(r"\d", new_password) or not re.search(r"[@#$%^&*]", new_password):
            return False, "Invalid new password structure."

        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT user_id FROM system_users WHERE account_username={p} AND account_email={p}",
                (username, email)
            )
            usr = cursor.fetchone()
            if not usr:
                return False, "No matching account found."

            enc_p = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            cursor.execute(
                f"INSERT INTO password_resets (user_id, account_email, new_hashed_password, request_time) VALUES ({p}, {p}, {p}, {p})",
                (usr[0], email, enc_p, time.time())
            )
            conn.commit()
            return True, "Password reset request submitted."
        finally:
            conn.close()


class InventoryController:
    @staticmethod
    def evaluate_status(qty):
        return "In Stock" if qty > 5 else ("Low Stock" if qty >= 1 else "Out of Stock")

    @staticmethod
    def get_all_items(search_text="", category="ALL"):
        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT asset_id, asset_name, asset_category, stock_qty, unit_val, stock_status FROM equipment_inventory WHERE 1=1"
            params = []
            if search_text:
                query += f" AND (asset_name LIKE {p} OR asset_category LIKE {p})"
                params.extend([f"%{search_text}%", f"%{search_text}%"])
            if category and category != "ALL":
                query += f" AND asset_category = {p}"
                params.append(category)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def get_categories():
        conn, _ = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT asset_category FROM equipment_inventory")
            cats = [row[0] for row in cursor.fetchall()]
            return cats
        finally:
            conn.close()

    @staticmethod
    def borrow_item(username, item_id, quantity):
        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(f"SELECT asset_name, stock_qty FROM equipment_inventory WHERE asset_id={p}", (item_id,))
            row = cursor.fetchone()
            if not row:
                return False, "Item not found."

            asset_name, stock_qty = row
            if quantity > stock_qty:
                return False, f"Requested quantity ({quantity}) exceeds stock ({stock_qty})."

            chk_time = time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                f"INSERT INTO lab_logbook (borrower_name, asset_id, asset_name, qty_borrowed, checkout_time, return_time) VALUES ({p}, {p}, {p}, {p}, {p}, 'PENDING_BORROW')",
                (username, item_id, asset_name, quantity, chk_time)
            )
            conn.commit()
            return True, "Borrow request submitted."
        finally:
            conn.close()

    @staticmethod
    def get_user_active_loans(username):
        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT log_id, asset_name, qty_borrowed, checkout_time, return_time FROM lab_logbook WHERE borrower_name={p} AND return_time='BORROWED'",
                (username,)
            )
            return cursor.fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_pending_borrows():
        conn, _ = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT log_id, borrower_name, asset_name, qty_borrowed, checkout_time FROM lab_logbook WHERE return_time='PENDING_BORROW'")
            return cursor.fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_pending_returns():
        conn, _ = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT log_id, borrower_name, asset_name, qty_borrowed, checkout_time FROM lab_logbook WHERE return_time='RETURN_PENDING'")
            return cursor.fetchall()
        finally:
            conn.close()

    @staticmethod
    def process_bulk_borrows(loan_ids, approve=True):
        if not loan_ids:
            return False, "No requests selected."

        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            for l_id in loan_ids:
                cursor.execute(f"SELECT asset_name, qty_borrowed FROM lab_logbook WHERE log_id={p}", (l_id,))
                record = cursor.fetchone()
                if not record:
                    continue
                asset_name, qty = record
                if approve:
                    cursor.execute(f"SELECT stock_qty FROM equipment_inventory WHERE asset_name={p}", (asset_name,))
                    inv = cursor.fetchone()
                    if inv and inv[0] >= qty:
                        new_qty = inv[0] - qty
                        new_status = InventoryController.evaluate_status(new_qty)
                        cursor.execute(
                            f"UPDATE equipment_inventory SET stock_qty={p}, stock_status={p} WHERE asset_name={p}",
                            (new_qty, new_status, asset_name)
                        )
                        cursor.execute(f"UPDATE lab_logbook SET return_time='BORROWED' WHERE log_id={p}", (l_id,))
                else:
                    cursor.execute(f"UPDATE lab_logbook SET return_time='REJECTED_BORROW' WHERE log_id={p}", (l_id,))
            conn.commit()
            return True, "Borrow requests processed."
        finally:
            conn.close()

    @staticmethod
    def request_bulk_item_returns(loan_ids):
        if not loan_ids:
            return False, "No items selected."

        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            for l_id in loan_ids:
                cursor.execute(f"UPDATE lab_logbook SET return_time='RETURN_PENDING' WHERE log_id={p}", (l_id,))
            conn.commit()
            return True, "Return requests submitted."
        finally:
            conn.close()

    @staticmethod
    def process_bulk_returns(loan_ids, approve=True):
        if not loan_ids:
            return False, "No requests selected."

        conn, p = get_db_connection()
        try:
            cursor = conn.cursor()
            ret_time = time.strftime("%Y-%m-%d %H:%M:%S")
            for l_id in loan_ids:
                cursor.execute(f"SELECT asset_name, qty_borrowed FROM lab_logbook WHERE log_id={p}", (l_id,))
                record = cursor.fetchone()
                if not record:
                    continue
                asset_name, qty = record
                if approve:
                    cursor.execute(f"SELECT stock_qty FROM equipment_inventory WHERE asset_name={p}", (asset_name,))
                    inv = cursor.fetchone()
                    if inv:
                        new_qty = inv[0] + qty
                        new_status = InventoryController.evaluate_status(new_qty)
                        cursor.execute(
                            f"UPDATE equipment_inventory SET stock_qty={p}, stock_status={p} WHERE asset_name={p}",
                            (new_qty, new_status, asset_name)
                        )
                    cursor.execute(f"UPDATE lab_logbook SET return_time={p} WHERE log_id={p}", (ret_time, l_id))
                else:
                    cursor.execute(f"UPDATE lab_logbook SET return_time='BORROWED' WHERE log_id={p}", (l_id,))
            conn.commit()
            return True, "Return requests processed."
        finally:
            conn.close()

    @staticmethod
    def export_to_csv():
        conn, _ = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT asset_id, asset_name, asset_category, stock_qty, unit_val, stock_status FROM equipment_inventory")
            rows = cursor.fetchall()
        finally:
            conn.close()

        filepath = os.path.join(os.getcwd(), "inventory_report.csv")
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Asset ID", "Name", "Category", "Quantity", "Unit Price", "Status"])
                writer.writerows(rows)
            return True, filepath
        except Exception as e:
            return False, str(e)