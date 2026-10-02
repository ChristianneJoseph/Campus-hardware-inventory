from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import sqlite3
import os
from Laboratorysystem import setup_database_tables, AuthController, InventoryController, DATABASE_FILE

app = Flask(__name__)
app.secret_key = "lab_experiment_7_secret_key"

setup_database_tables()

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        ok, msg, role, is_locked, email = AuthController.login_user(username, password)
        if ok:
            session["username"] = username
            session["role"] = role
            flash(msg, "success")
            return redirect(url_for("dashboard"))
        else:
            flash(msg, "danger")
            return render_template("login.html", locked=is_locked, locked_username=username if is_locked else None)
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "USER").strip()

        ok, msg = AuthController.register_user(username, email, password, role)
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/reset_request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset.html")

        ok, msg = AuthController.submit_password_reset_request(username, email, new_password)
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("login"))
    return render_template("reset.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "")
    category = request.args.get("category", "ALL")

    items = InventoryController.get_all_items(search, category)
    categories = InventoryController.get_categories()
    
    all_items = InventoryController.get_all_items("", "ALL")
    total_stocks = sum([item[3] for item in all_items])

    active_loans = []
    pending_borrows = []
    pending_returns = []

    if session["role"] == "USER":
        active_loans = InventoryController.get_user_active_loans(session["username"])
    elif session["role"] == "ADMIN":
        pending_borrows = InventoryController.get_pending_borrows()
        pending_returns = InventoryController.get_pending_returns()

    return render_template(
        "dashboard.html",
        items=items,
        categories=categories,
        total_stocks=total_stocks,
        search=search,
        selected_category=category,
        active_loans=active_loans,
        pending_borrows=pending_borrows,
        pending_returns=pending_returns
    )

@app.route("/item/add", methods=["POST"])
def add_item():
    if session.get("role") != "ADMIN":
        return redirect(url_for("dashboard"))

    asset_name = request.form.get("asset_name")
    category = request.form.get("category")
    stock_qty = int(request.form.get("stock_qty"))
    unit_val = float(request.form.get("unit_val"))
    status = InventoryController.evaluate_status(stock_qty)

    try:
        db_conn = sqlite3.connect(DATABASE_FILE)
        cursor = db_conn.cursor()
        cursor.execute(
            "INSERT INTO equipment_inventory (asset_name, asset_category, stock_qty, unit_val, stock_status) VALUES (?, ?, ?, ?, ?)",
            (asset_name, category, stock_qty, unit_val, status)
        )
        db_conn.commit()
        db_conn.close()
        flash("Item added successfully!", "success")
    except sqlite3.IntegrityError:
        flash("An item with this name already exists.", "danger")

    return redirect(url_for("dashboard"))

@app.route("/item/edit", methods=["POST"])
def edit_item():
    if session.get("role") != "ADMIN":
        return redirect(url_for("dashboard"))

    asset_id = int(request.form.get("asset_id"))
    asset_name = request.form.get("asset_name")
    category = request.form.get("category")
    stock_qty = int(request.form.get("stock_qty"))
    unit_val = float(request.form.get("unit_val"))
    status = InventoryController.evaluate_status(stock_qty)

    db_conn = sqlite3.connect(DATABASE_FILE)
    cursor = db_conn.cursor()
    cursor.execute(
        "UPDATE equipment_inventory SET asset_name=?, asset_category=?, stock_qty=?, unit_val=?, stock_status=? WHERE asset_id=?",
        (asset_name, category, stock_qty, unit_val, status, asset_id)
    )
    db_conn.commit()
    db_conn.close()
    
    flash("Item updated successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/item/delete/<int:asset_id>", methods=["POST"])
def delete_item(asset_id):
    if session.get("role") != "ADMIN":
        return redirect(url_for("dashboard"))

    db_conn = sqlite3.connect(DATABASE_FILE)
    cursor = db_conn.cursor()
    cursor.execute("DELETE FROM equipment_inventory WHERE asset_id=?", (asset_id,))
    db_conn.commit()
    db_conn.close()

    flash("Item deleted successfully!", "danger")
    return redirect(url_for("dashboard"))

@app.route("/borrow", methods=["POST"])
def borrow():
    if "username" not in session:
        return redirect(url_for("login"))

    item_id = int(request.form.get("item_id"))
    quantity = int(request.form.get("quantity"))

    ok, msg = InventoryController.borrow_item(session["username"], item_id, quantity)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/return_request", methods=["POST"])
def return_request():
    if "username" not in session:
        return redirect(url_for("login"))

    loan_ids = [int(id_) for id_ in request.form.getlist("loan_ids")]
    ok, msg = InventoryController.request_bulk_item_returns(loan_ids)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/borrow_action", methods=["POST"])
def admin_borrow_action():
    if session.get("role") != "ADMIN":
        return redirect(url_for("dashboard"))

    loan_ids = [int(id_) for id_ in request.form.getlist("loan_ids")]
    action = request.form.get("action")
    approve = (action == "approve")

    ok, msg = InventoryController.process_bulk_borrows(loan_ids, approve)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/return_action", methods=["POST"])
def admin_return_action():
    if session.get("role") != "ADMIN":
        return redirect(url_for("dashboard"))

    loan_ids = [int(id_) for id_ in request.form.getlist("loan_ids")]
    action = request.form.get("action")
    approve = (action == "approve")

    ok, msg = InventoryController.process_bulk_returns(loan_ids, approve)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/export")
def export():
    if "username" not in session:
        return redirect(url_for("login"))

    ok, filepath = InventoryController.export_to_csv()
    if ok:
        return send_file(filepath, as_attachment=True, download_name="inventory_report.csv")
    else:
        flash(f"Export failed: {filepath}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)