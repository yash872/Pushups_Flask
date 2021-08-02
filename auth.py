from flask import Blueprint, render_template, url_for, request, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db

auth = Blueprint('auth',__name__)

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup',methods=['POST'])
def signup_post():
    name = request.form.get('Name')
    email = request.form.get('Email')
    password = request.form.get('Password')

    #print(email,name,password)
    user = User.query.filter_by(email=email).first()
    if user:
        print("User is already exists!")
        return redirect(url_for('auth.signup'))
    else:
        new_user = User(email=email, name=name, password=generate_password_hash(password,method='sha256'))
        db.session.add(new_user)
        db.session.commit()
        print("User {} is created!".format(name))

    return redirect(url_for('auth.login'))



@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login',methods=['POST'])
def login_post():
    email = request.form.get('Email')
    password = request.form.get('Password')

    # print(email,password)

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash('Email or Password wrong!', 'error')
        return redirect(url_for('auth.login'))
    
    login_user(user)
    return redirect(url_for('main.profile'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))