from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# user model
class User(db.Model):
    __tablename__ = "users"
    email = db.Column(db.String(120), primary_key=True, unique=True)
    salt =  db.Column(db.String(256), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    messages = db.relationship("Message", backref="users", lazy=True)

    def __init__(self, email, salt, password, confirmed):
        self.email = email
        self.salt = salt
        self.password = password
        self.confirmed = confirmed

    def __repr__(self):
        return "<User %r>" % self.email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.email)

# message model
class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(120), nullable=False)
    recipient = db.Column(db.String(120), db.ForeignKey('users.email'), nullable=False)
    sender = db.Column(db.String(120), nullable=False)

    def __init__(self, message, recipient, sender):
        self.message = message
        self.recipient = recipient
        self.sender = sender

