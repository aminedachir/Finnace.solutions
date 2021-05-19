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
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == 'POST':
        symbol = lookup(request.form.get("symbol"))

        if symbol == None:
            return ("<script>alert('Invalid quote')</script>")

        shares = lookup(request.form.get("shares"))

        if shares == int:
            return redirect("/")

        else:
            return ("<script>alert('not int')</script>")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")

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

        elif password1 != password2:
            return "<script>alert('password and confirm password not match')</script>"

        else:
            password = generate_password_hash(password1)

            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=password)

            session["user_id"] = db.execute("SELECT id FROM users WHERE username = :username", username=username)[0]["id"]

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
            return apology("invalid username and/or password", 403)

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
    if request.method == 'POST':
        quotee = lookup(request.form.get("symbol"))

        if quotee == None:
            return ("<script>alert('Invalid quote')</script>")
        else:
            return render_template("quotee.html", quotee=quotee)

    else:
        return render_template("quote.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
