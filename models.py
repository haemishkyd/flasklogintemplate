from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import validates
from flask_login import UserMixin

from app import db

class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    CurrentActivity = db.Column(db.Integer, nullable=False)

    def __str__(self):
        return self.name

class Activities(db.Model):
    __tablename__ = 'activities'
    activityid = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(50), nullable=False)

    def __str__(self):
        return self.name

class ActivityProgress(db.Model):
    __tablename__ = 'activityprogress'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    #user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    #activity_id = db.Column(db.Integer, db.ForeignKey('activities.activityid'), nullable=False)
    activity_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    distance = db.Column(db.Float, nullable=False)

    def __str__(self):
        return self.name