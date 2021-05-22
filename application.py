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
    stocks = db.execute("SELECT stock_symbol, no_shares FROM stocks WHERE user_id = ?", session["user_id"])
    total = cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    info = []
    for i in range(len(stocks)):
        info.append(lookup(stocks[i]["stock_symbol"]))
        info[i]["shares"] = stocks[i]["no_shares"]
        info[i]["total"] = usd(info[i]["shares"] * info[i]["price"])
        total += info[i]["shares"] * info[i]["price"]
        info[i]["price"] = usd(info[i]["price"])

    return render_template("index.html", stocks=stock_info, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":

        stock = lookup(request.form.get("symbol"))

        if stock == None:
            return "<script>alert('Invalid Symbol')</script>"

        shares = int(request.form.get("shares"))

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        amount = shares*stock["price"]
        if amount > cash:
            return "<script>alert('Can't Afford')</script>"
    prev_stocks = db.execute("SELECT no_shares FROM stocks WHERE user_id = ? AND stock_symbol = ?",
                                 session["user_id"], stock["symbol"])

        if len(prev_stocks) != 0:
            prev_shares = prev_stocks[0]["no_shares"]
            db.execute("UPDATE stocks SET no_shares = ? WHERE user_id = ? AND stock_symbol = ?",
                       prev_shares+shares, session["user_id"], stock["symbol"])
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash-req_amount, session["user_id"])

        else:
            db.execute("INSERT INTO stocks (user_id, stock_symbol, no_shares) VALUES (?, ? , ?)",
                       session["user_id"], stock["symbol"], shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash-req_amount, session["user_id"])

        now = datetime.now()
        transacted = now.strftime("%H:%M:%S %d/%m/%Y")
        db.execute("INSERT INTO history (id, symbol, price, total, shares, datetime) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], stock["symbol"], usd(stock["price"]), usd(req_amount), shares, transacted)

        return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    stocks = db.execute(
        "SELECT symbol, shares, price, total, datetime FROM history WHERE id = ? ORDER BY sr DESC", session["user_id"])
    return render_template("history.html", stocks=stocks)

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
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        amount = shares*stock["price"]

        db.execute("UPDATE stocks SET no_shares = ? WHERE user_id = ? AND stock_symbol = ?",
                   prev_shares-shares, session["user_id"], stock["symbol"])

        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash+amount, session["user_id"])

        now = datetime.now()
        transacted = now.strftime("%H:%M:%S %d/%m/%Y")
        db.execute("INSERT INTO history (id, symbol, price, total, shares, datetime) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], stock["symbol"], usd(stock["price"]), usd(amount), -shares, transacted)

        return redirect("/")

    else:
        stocks = db.execute("SELECT stock_symbol, no_shares FROM stocks WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
