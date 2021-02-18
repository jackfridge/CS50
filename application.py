import os
import string

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError

# security lib from flask for password hashing
from werkzeug.security import check_password_hash, generate_password_hash

# from helpers import apology, login_required
from helpers import login_required

from datetime import datetime
import time

import sqlite3

# Configure application
app = Flask(__name__)

# HOWTO RUN FLASK IN VSCODE
# $ export FLASK_APP=application.py
# $ flask run

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure SQL (get a library to access and do some db.execute)
db_conn = sqlite3.connect("database.db", check_same_thread=False)
db = db_conn.cursor()

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/browse")
@login_required
def browse():
    return render_template("browse.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """ Log in the user """
    # Forget any user logged in
    session.clear()

    if request.method == "POST":
        # Set variables from HTML form to validate login
        user = request.form.get("username")
        password = request.form.get("password")

        db.execute("SELECT * FROM users WHERE username=?", (user,))
        user_check = db.fetchone()
        print(user_check)
        # Make sure the username is valid
        if user_check == None:
            # This username is invalid
            print("username does not exist")
            return render_template("login.html", msg="This username does not exist")

        else:
            # Validate password hashes match
            hash = user_check[2]
            print(user_check[2])
            if check_password_hash(hash, password):
                # Successful login
                session["user_id"] = user_check[0]
                return render_template("index.html", reg="You have successfully logged in!")

            else:
                # Wrong password was input
                return render_template("login.html", msg="Wrong password")
    else:
        return render_template("/login.html")


@app.route("/logout")
def logout():
    """ Log out the user """
    session.clear()

    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Store values from HTML form
        user = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        email = request.form.get("email")

        if not user or not password or not confirmation:
            # Invalid input, must type something out
            return render_template("register.html", msg="Please verify you filled out the required fields")

        if password != confirmation:
            # Passwords don't match
            return render_template("register.html", msg="Passwords do not match")

        # Make sure the password matches all required strength parameters
        if (any(x.islower() for x in password) == False):
            return render_template("register.html", msg="Password must contain at least 1 lowercase letter")

        if (any(x.isupper() for x in password) == False):
            return render_template("register.html", msg="Password must contain at least 1 uppercase letter")
        
        if (any(x.isdigit() for x in password) == False):
            return render_template("register.html", msg="Password must contain at least 1 number")
        
        if (len(password) < 8):
            return render_template("register.html", msg="Password must be at least 8 characters long")
        
        # Variable to check if anything returns for the input username
        db.execute("SELECT * FROM users WHERE username=?", (user,))
        check_user = db.fetchone()
        
        # Make sure the username doesn't yet exist in db
        if check_user != None:
            # This username exists (export to HTML?)
            return render_template("register.html", msg="This username already exists")
        
        # Create user in db
        else:
            db.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (user, generate_password_hash(password), email))
            # Commit sql INSERT into db file
            db_conn.commit()

            # Redirect to login page
            return render_template("register.html", reg="You have successfully registered!")

    else:
        return render_template("register.html")


def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    # try to return an alert on the same page
    # for now, return a default page with the code showing
    return render_template("debug.html", e=e)


#Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

