import os

from datetime import datetime
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
    row = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    remn = row[0]["cash"]
    lines = db.execute("SELECT symbol, SUM(shares) AS shares_total, name FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING shares_total > 0 ORDER BY symbol ASC", user_id=session["user_id"])
    if lines != None:
        ttlshares = 0
        portfo = {line["symbol"] : lookup(line["symbol"]) for line in lines}
        for line in lines:
            ttlshares += (portfo[line["symbol"]]["price"] * line["shares_total"])
    ttlshares += remn
    return render_template("index.html", remn=round(float(remn), 2), lines=lines, portfo=portfo, ttlshares=float(ttlshares))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        checkbuyvalues = request.form.get("symbol")
        if checkbuyvalues.count("'") != 0 or checkbuyvalues.count(";") != 0:
            return apology("Nice try, Mr Little Bobby Tables", 403)
        shares = int(request.form.get("shares"))
        market = lookup(checkbuyvalues)
        if market == None:
            return apology("Invalid market.", 400)
        value = market["price"]
        total = value * shares
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        cash = rows[0]["cash"]
        if total > cash:
            return apology("You don't have enough money.", 403)
        db.execute("UPDATE users SET cash = cash - :total WHERE id = :user_id", total=total, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, transacted) VALUES(:user_id, :symbol, :name, :shares, :price, :transacted)",
                   user_id=session["user_id"],
                   symbol=request.form.get("symbol").upper(),
                   name=market["name"],
                   shares=shares,
                   price=value,
                   transacted=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        flash("Bought!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    lines = db.execute("SELECT * FROM transactions WHERE user_id = :user_id ORDER BY transacted ASC", user_id=session["user_id"])
    return render_template("history.html", lines=lines)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        checkloginvalues = []
        checkloginvalues.append(request.form.get("username"))
        checkloginvalues.append(request.form.get("password"))
        if checkloginvalues.count("'") != 0 or checkloginvalues.count(";") != 0:
            return apology("Nice try, Mr Little Bobby Tables", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
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
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Please enter a market.", 400)
        symbol = request.form.get("symbol").upper()
        checksymbolvalues=request.form.get("symbol")
        if checksymbolvalues.count("'") != 0 or checksymbolvalues.count(";") != 0:
            return apology("Nice try, Mr Little Bobby Tables", 403)
        market = lookup(symbol)
        if market == None:
            return apology("Invalid market.", 400)
        return render_template("value.html", market=market)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Must provide username", 403)
        elif not request.form.get("password"):
            return apology("Must provide password", 403)
        elif not any(i.isdigit() for i in request.form.get("password")):
            return apology("Password must contain at least one digit", 403)
        checkregistervalues = []
        checkregistervalues.append(request.form.get("username"))
        checkregistervalues.append(request.form.get("password"))
        checkregistervalues.append(request.form.get("confirmation"))
        if checkregistervalues.count("'") != 0 or checkregistervalues.count(";") != 0:
            return apology("Nice try, Mr Little Bobby Tables")
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("The passwords doesn't match")
        try:
            key = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                        username=request.form.get("username"),
                        hash=generate_password_hash(request.form.get("password")))
        except:
            return apology("Username already taken.", 403)
        session["user_id"] = key
        if key == None:
                return apology("Username already taken.", 403)
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    lines = db.execute("SELECT symbol, SUM(shares) AS shares_total, name FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING shares_total > 0 ORDER BY symbol ASC", user_id=session["user_id"])
    if request.method == "POST":
        checkbuyvalues = request.form.get("shares")
        if checkbuyvalues.count("'") != 0 or checkbuyvalues.count(";") != 0:
            return apology("Nice try, Mr Little Bobby Tables", 403)
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        market = lookup(symbol)
        sellingmarket = db.execute("SELECT symbol, SUM(shares) AS shares_total, name FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol ORDER BY symbol ASC", user_id=session["user_id"], symbol=symbol)
        if int(shares) > int(sellingmarket[0]["shares_total"]):
            return apology("You don't have enough shares", 400)
        total = float(market["price"]) * int(shares)
        db.execute("UPDATE users SET cash = cash + :total WHERE id = :user_id", total=total, user_id=session["user_id"])
        shares = -(int(shares) * 1)
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, transacted) VALUES(:user_id, :symbol, :name, :shares, :price, :transacted)",
                   user_id=session["user_id"],
                   symbol=symbol,
                   name=market["name"],
                   shares=shares,
                   price=market["price"],
                   transacted=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        flash("Sold!")
        return redirect("/")

    else:
        return render_template("sell.html", lines=lines)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
