import os
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)
# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required
def index():
    total = amount = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    return render_template("index.html",amount=usd(amount),username=username )

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return "<script>alert('Invalid Symbol')</script>"
        shares = int(request.form.get("shares"))
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if amount > cash:
            return "<script>alert('Can't Afford')</script>"
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    #stocks = db.execute(
        #"SELECT symbol, shares, price, total, datetime FROM history WHERE id = ? ORDER BY sr DESC", session["user_id"])
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    return render_template("history.html", username= username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password1 = request.form.get("password")
        password2 = request.form.get("confirm")
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)
        if len(rows) != 0:
            return "<script>alert('username exists')</script>"
        x = password1.isalpha()
        if x == True:
            return "<script>alert('should write one number minumum in your password')</script>"

        elif username == password1:
            return "<script>alert('don't write your username in password)</script>"
        elif len(password1) < 8:
            return "<script>alert('password should take 8 letter a min')</script>"
        elif password1 != password2:
            return "<script>alert('password and confirm password not match')</script>"
        else:
            password = generate_password_hash(password1)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=password)
            session["user_id"] = db.execute("SELECT id FROM users WHERE username = :username", username=username)[0]["id"]
            flash("registered !")
            return redirect("/")
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password Try again!", 403)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return "<script>alert('Invalid symbol')</script>"
        return render_template("quoted.html", stock=stock)
    else:
        return render_template("quote.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == 'POST':
        shares = int(request.form.get("shares"))
        if shares == 0:
            return "<script>alert('enter a number of shares')</script>"
        stock = lookup(request.form.get("symbol"))
        stocks = db.execute("SELECT no_shares FROM stocks WHERE user_id = ? AND stock_symbol = ?",
                                 session["user_id"], stock["symbol"])
        sharess = stocks[0]["not shares"]
        if shares > sharess:
            return "<script>alert('You do not have this number of shares')</script>"
        return render_template("sell.html", stocks=stocks)
    else:
        return render_template("sell.html")

@app.route("/setting", methods = ['GET', 'POST'])
@login_required
def setting():
    if request.method == "POST":
        old = request.form.get("old")
        new_password = request.form.get("new_password")
        confirm_npassword = request.form.get("confirm_npassword")
        if new_password != confirm_npassword:
            return "<script>alert('Passwords Didn't match')</script>"
        hashe = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])[0]["hash"]
        if not check_password_hash(hashe, old):
            return "<script>alert('Incorrect Password')</script>"
        else:
            newpassword = generate_password_hash(new_password)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", newpassword, session["user_id"])
        flash("Password changed")
        return redirect("/")
    else:
        return render_template("setting.html")

@app.route("/cash", methods=['GET', 'POST'])
@login_required
def cash():
    if request.method == 'POST':
        db.execute("UPDATE users SET cash = cash+:amount WHERE id =:user_id ",amount = request.form.get("cash"),user_id = session["user_id"])
        flash("Cash Added")
        return redirect("/")
    else:
        return render_template("cash.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
