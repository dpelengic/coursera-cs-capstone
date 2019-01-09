from models import db, User, Message
from flask import Flask, flash, request, render_template, redirect, url_for, send_file, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from forms import RegisterForm, RegisterFormRecaptcha, LoginForm, LoginFormRecaptcha, MessageForm
from cryptography.fernet import Fernet
from gevent import monkey
monkey.patch_all()
from gevent import wsgi
import os
import sqlite3, zipfile
import uuid

app = Flask(__name__)
bcrypt = Bcrypt(app)

# sqlite database path
DB_PATH="/opt/data/database.sqlite"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+DB_PATH

# if it exists, use predefined secret from environment variable
if "SECRET" in os.environ:
    app.secret_key = os.environ["SECRET"]
# else create a new one
else: 
    app.secret_key = str(uuid.uuid4())

# if it exists, use predefined cipher for encryption/decryption from environment variable
if "CIPHER" in os.environ:
    cipher_key = os.environ["CIPHER"]
# else create a new one -> this makes existing users unable to login
else:
    cipher_key = Fernet.generate_key() 

# if it exists, use predefined recaptcha private and public keys
if "RECAPTCHA_PUBLIC_KEY" in os.environ and "RECAPTCHA_PRIVATE_KEY" in os.environ:
    # recaptcha, must be configured for domain and/or localhost
    app.config["RECAPTCHA_PUBLIC_KEY"] = os.environ["RECAPTCHA_PUBLIC_KEY"]
    app.config["RECAPTCHA_PRIVATE_KEY"] = os.environ["RECAPTCHA_PRIVATE_KEY"] 
    recaptcha_enabled = True
# else, disable recaptcha
else:
    recaptcha_enabled = False

# init crypto Fernet
cipher = Fernet(cipher_key)

# init login manager
login_manager = LoginManager()
login_manager.init_app(app)

# route definitions
@app.route("/")
def index():
     return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    # use form with, or without recaptcha    
    if recaptcha_enabled:
        form = RegisterFormRecaptcha()
    else:
        form = RegisterForm()

    ### GET
    if request.method == "GET":
        return render_template("register.html", form = form, recaptcha_enabled = recaptcha_enabled)

    ### POST
    elif request.method == "POST":

        # validate form
        if form.validate_on_submit():

            # validate both passwords match
            if form.password.data != form.confirmpassword.data:
                error = "Passwords must match."
                return render_template("register.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

            # validate email is not already in database 
            if User.query.filter_by(email = form.email.data).first():
                error = "Email address already in use."
                return render_template("register.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

            else:
                # create a random salt and encrypt it
                user_salt = str(uuid.uuid4())
                enc_user_salt = cipher.encrypt(user_salt)
                # mark user as not confirmed
                confirmed = False
                # hash password, then insert into the database
                password_hash = bcrypt.generate_password_hash(user_salt+"#"+form.password.data)
                newuser = User(form.email.data, enc_user_salt, password_hash, confirmed)
                db.session.add(newuser)
                db.session.commit()
                flash("Account created. You may now login.")
                return redirect(url_for("login"))

        # form did not validate
        else:
            if form.recaptcha.errors:
                error = "Recaptcha error."
            elif form.email.errors:
                error = "Invalid email."
            elif form.password.errors:
                error = "Invalid password."
            elif form.confirmpassword.errors:
                error = "Passwords must match."

            return render_template("register.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

    # handle other request methods
    else:
        error = "Method not allowed"
        return render_template("register.html", form = form, error = error)

@app.route("/login", methods=["GET","POST"])
def login():

    # use form with, or without recaptcha    
    if recaptcha_enabled: 
        form = LoginFormRecaptcha()
    else:    
        form = LoginForm()

    ### GET
    if request.method == "GET":
        return render_template("login.html", form = form, recaptcha_enabled = recaptcha_enabled)

    ### POST
    elif request.method == "POST":

        # validate form
        if form.validate_on_submit():
            # fetch user from database
            user=User.query.filter_by(email=form.email.data).first()

            # validate user
            if user:
                # decrypt user salt
                dec_user_salt = cipher.decrypt(str(user.salt))

            # user does not exist in our database
            else:
                error = "User does not exist."
                return render_template("login.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

            # validate passwords match
            if not bcrypt.check_password_hash(user.password, dec_user_salt+"#"+form.password.data):
                error = "Incorrect password."
                return render_template("login.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

            # passwords match, proceed to login user
            else:
                login_user(user)
                flash("Successfully logged in.")
                return redirect(url_for("inbox"))

        # form does not match
        else:
            if form.recaptcha.errors:
                error = "Recaptcha error."
            elif form.email.errors:
                error = "Invalid email."
            elif form.password.errors:
                error = "Invalid password."

            return render_template("login.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

    # handle other request methods
    else:
        error = "Method not allowed"
        return render_template("login.html", form = form, error = error, recaptcha_enabled = recaptcha_enabled)

@app.route("/inbox", methods=["GET", "POST"])
#@login_required
def inbox():
    form = MessageForm()

    ### GET
    if request.method == "GET":

        # check if user authenticated
        if current_user.is_authenticated:
            # fetch user messages from db
            dec_user_messages = []
            user = current_user.get_id()
            user_messages = Message.query.filter_by(recipient = user).all()

        # user not authenticated
        else:
            # nothing
            flash("Please login first.")
            return redirect(url_for("index"))

        # if there are any messages, decrypt them
        if user_messages:
            for user_message in user_messages:
                dec_message = Message(cipher.decrypt(str(user_message.message)), user, cipher.decrypt(str(user_message.sender)))
                dec_user_messages.extend([dec_message])

        return render_template("inbox.html", form = form, user_messages = dec_user_messages)

    ### POST
    elif request.method == "POST":

        # user not authenticated
        if not current_user.is_authenticated:
            # nothing
            flash("Please login first.")
            return redirect(url_for("index"))

        # validate form
        if form.validate_on_submit():

            # validate user
            if not User.query.filter_by(email=form.email.data).first():
                error = "Recipient email not found in our records. Message not sent."
                user = current_user.get_id()
                user_messages = Message.query.filter_by(recipient = user).all()
                return render_template("inbox.html", form = form, error = error, user_messages = user_messages, last_menu_msg = "last_menu_msg")
                
            # user validated, proceed
            else:
                user = current_user.get_id()
                # encrypt the message and sender
                encrypted_message_body = cipher.encrypt(str(form.message.data))
                encrypted_message_sender = cipher.encrypt(str(user))
                # insert message, recipient, sender
                newmessage = Message(encrypted_message_body, form.email.data, encrypted_message_sender)
                db.session.add(newmessage)
                db.session.commit()
                flash("Message sent!")
                return redirect(url_for("inbox"))

        # form does not match
        else:
            error = "Invalid recipient email."
            user = current_user.get_id()
            user_messages = Message.query.filter_by(recipient = user).all()
            return render_template("inbox.html", form = form, error = error, user_messages = user_messages, last_menu_msg = "last_menu_msg")

    # handle other request methods
    else:
        error = "Method not allowed"
        return redirect(url_for("inbox"))

@app.route("/dbdump", methods=["GET"])
#@login_required
def dbdump():

    if request.method == "GET":

        # get DB dump in memory
        conn = sqlite3.connect(DB_PATH)
        dump_data = '\n'.join(conn.iterdump())
        conn.close()
        # zip the dump data into a file
        dumpfile = str(uuid.uuid4())+".dump.zip"
        zfile = zipfile.ZipFile(dumpfile, mode="w", compression=zipfile.ZIP_DEFLATED)
        zfile.writestr("dump.sql", dump_data)
        zfile.close()
        return send_file(dumpfile, as_attachment=True)

    # handle other request methods
    else:
        error = "Method not allowed"
        return render_template("index.html", error = error)

@app.route("/logout")
#@login_required
def logout():

    if request.method == "GET":

        # check if user authenticated
        if current_user.is_authenticated:
            logout_user()
            flash("Successfully logged out.")
            return redirect(url_for("index"))

        # user not authenticated
        else:
            # nothing
            flash("Please login first.")
            return redirect(url_for("index"))

    # handle other request methods
    else:
        error = "Method not allowed"
        return render_template("index.html", error = error)

@login_manager.user_loader
def load_user(email):
    return User.query.filter_by(email = email).first()

# do not cache responses
@app.after_request
def set_response_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# if it does not exist, init database, and populate with defined models
def init_db():
    db.init_app(app)
    db.app = app
    db.create_all()

if __name__ == "__main__":
    init_db()
    app.debug = True
    #app.run(port=5000, host="localhost")
    # run server
    server = wsgi.WSGIServer(('127.0.0.1', 5000), app)
    server.serve_forever()
