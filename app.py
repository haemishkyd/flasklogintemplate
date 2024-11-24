from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate

import os,sys,jwt
from datetime import datetime,date,timedelta

app = Flask(__name__, static_folder='static')

# WEBSITE_HOSTNAME exists only in production environment
if 'WEBSITE_HOSTNAME' not in os.environ:
    # local development, where we'll use environment variables
    print("Loading config.development and environment variables from .env file.")
    app.config.from_object('azureproject.development')
else:
    # production
    print("Loading config.production.")
    app.config.from_object('azureproject.production')

app.config.update(
    SQLALCHEMY_DATABASE_URI=app.config.get('DATABASE_URI'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

CORS(app)
app.app_context().push()
jwt = JWTManager(app)

db = SQLAlchemy(app)

from models import Users, Activities, ActivityProgress

# Enable Flask-Migrate commands "flask db init/migrate/upgrade" to work
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# numofUsers = db.session.query(Users).count()
# print("Number of users: ", numofUsers)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")

@app.route("/")
@login_required
def index():
    activities = Activities.query.all()
    return render_template("index.html", activities=activities)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data, method="scrypt")
        new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("You've been registered successfully, now you can log in.")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember)
            return redirect(url_for("index"))
        return "Your credentials are invalid."
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You were logged out. See you soon!")
    return redirect(url_for("login"))

@app.route("/api/activities", methods=["GET"])
@jwt_required()
def get_activities():
    current_user = get_jwt_identity()
    print(current_user)
    activities = Activities.query.all()
    activities_list = [{"activityid": activity.activityid, "description": activity.description} for activity in activities]
    return jsonify(activities_list)

@app.route("/api/login", methods=["POST"])
def apilogin():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Invalid input"}), 400

    user = Users.query.filter_by(username=data["username"]).first()

    if user and check_password_hash(user.password, data["password"]):
        login_user(user)
        access_token = create_access_token(identity={'username': data["username"]})
        return jsonify({"message": "Login successful", "token": access_token, "id": user.id}), 200

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/add_activities_progress", methods=["POST"])
@jwt_required()
def add_user_activity():
    data = request.get_json()

    if not data or not data.get("user_id") or not data.get("activity_id") or not data.get("date") or not data.get("time") or not data.get("distance"):
        return jsonify({"error": "Invalid input"}), 400
    print(data)
    try:
        new_activity = ActivityProgress(
            user_id=data["user_id"],
            activity_id=data["activity_id"],
            date=datetime.strptime(data["date"], "%Y-%m-%d").date(),
            time=datetime.strptime(data["time"], "%H:%M:%S").time(),
            distance=data["distance"]
        )
        print (new_activity.time)
        db.session.add(new_activity)
        db.session.commit()    
        return jsonify({"message": "Activity added successfully"}), 201
    except Exception as e:
        print (str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/get_activities_progress/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user_activities(user_id):
    try:
        # Get the current date
        today = date.today()
        # Get the first and last day of the current month
        first_day_of_month = today.replace(day=1)
        last_day_of_month = (today.replace(month=today.month % 12 + 1, day=1) - timedelta(days=1))

        # Query the activities for the specified user and current month
        activities = ActivityProgress.query.filter(
            ActivityProgress.user_id == user_id,
            ActivityProgress.date >= first_day_of_month,
            ActivityProgress.date <= last_day_of_month
        ).all()
        print (activities)
   
        # Convert the activities to a list of dictionaries
        activities_list = [
            {
                "id": activity.id,
                "activity_id": activity.activity_id,
                "date": activity.date.strftime("%Y-%m-%d"),
                "time": activity.time.strftime("%H:%M:%S"),
                "distance": activity.distance
            }
            for activity in activities
        ]

        return jsonify(activities_list), 200
    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500
    
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
