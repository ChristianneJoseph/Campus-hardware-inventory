import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from Laboratorysystem import AuthController, InventoryController

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "exp7-secret-key-dev")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "ADMIN":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "username" in session else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        ok, msg, role, is_locked, email = AuthController.login_user(username, password)
        if ok:
            session.clear()
            session["username"] = username
            session["role"] = role
            session["email"] = email
            flash(msg, "success")
            return redirect(url_for("dashboard"))
        
        flash(msg, "danger")
        return render_template("login.html", locked=is_locked, locked_username=username)
        
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "USER").strip().upper()

        ok, msg = AuthController.register_user(username, email, password, role=role)
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("login"))
            
    return render_template("register.html")

@app.route("/reset-request", methods=["GET", "POST"])
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
@login_required
def dashboard():
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "ALL")

    items = InventoryController.get_all_items(search_text=search, category=category)
    categories = InventoryController.get_categories()
    
    all_items = InventoryController.get_all_items(search_text="", category="ALL")
    total_stocks = sum(item[3] for item in all_items)

    active_loans, history, pending_returns, pending_borrows, pending_resets = [], [], [], [], []

    if session["role"] == "USER":
        active_loans = InventoryController.get_user_active_loans(session["username"])
        history = InventoryController.get_user_loan_history(session["username"])
    else:
        pending_returns = InventoryController.get_pending_returns()
        pending_borrows = InventoryController.get_pending_borrows()
        pending_resets = AuthController.get_pending_resets()

    return render_template(
        "dashboard.html",
        items=items,
        categories=categories,
        search=search,
        selected_category=category,
        total_stocks=total_stocks,
        active_loans=active_loans,
        history=history,
        pending_returns=pending_returns,
        pending_borrows=pending_borrows,
        pending_resets=pending_resets
    )

@app.route("/borrow", methods=["POST"])
@login_required
def borrow():
    try:
        item_id = int(request.form["item_id"])
        quantity = int(request.form.get("quantity", 1))
    except (KeyError, ValueError):
        flash("Invalid borrow parameters.", "danger")
        return redirect(url_for("dashboard"))

    if session["role"] != "USER":
        flash("Only user accounts can submit borrow requests.", "danger")
        return redirect(url_for("dashboard"))

    ok, msg = InventoryController.borrow_item(session["username"], item_id, quantity)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/return-request", methods=["POST"])
@login_required
def return_request():
    raw_ids = request.form.getlist("loan_ids")
    loan_ids = [int(x) for x in raw_ids if x.isdigit()]
    
    ok, msg = InventoryController.request_bulk_item_returns(loan_ids)
    flash(msg, "success" if ok else "warning")
    return redirect(url_for("dashboard"))

@app.route("/admin/borrow-action", methods=["POST"])
@admin_required
def admin_borrow_action():
    raw_ids = request.form.getlist("loan_ids")
    loan_ids = [int(x) for x in raw_ids if x.isdigit()]
    approve = request.form.get("action") == "approve"

    ok, msg = InventoryController.process_bulk_borrows(loan_ids, approve=approve)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Successfully logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)