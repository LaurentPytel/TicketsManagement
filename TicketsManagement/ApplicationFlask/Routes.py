from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from ApplicationFlask import app, database, auth
from flask_login import login_user, login_required, current_user
import json




@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def profile():
    user = current_user
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        return 'You are not logged in!'

    

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email    = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    
    UsersCollection = database.Users;
    myquery = { "email": email }
    myUser = auth.User.get_by_email(email)
    
    if auth.User.login_valid(myUser, password):
        loguser = auth.User(myUser._id, myUser.email, myUser.password)
        login_user(myUser, remember)
        flash('You have been logged in!', 'success')
        return redirect(url_for('profile'))
    else:
        flash('Login Unsuccessful. Please check email and password', 'danger')        
        return redirect(url_for('login'))


@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    
    email = request.form.get('email')
    username = request.form.get('name')
    password = request.form.get('password')
    encryptedPassword = generate_password_hash(password, method='sha256')

    
    myUser = auth.User.get_by_email(email)
    if myUser is None:
        auth.User.register(username, email, encryptedPassword)
        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('login'))
    else:
        flash('Email address already exists')
        return redirect(url_for('signup'))




@app.route('/logout')
def logout():
    return 'Logout'




@app.route('/newClient')
def newClients():
    
    ClientsCollection = database.Clients;

    newClient = { "Name":"Pytel", "Firstname":"Laurent" }

    x=ClientsCollection.insert_one(newClient)
    print(x)
    return "Client inserted"

@app.route('/listClients')
def listClients():
    
    ClientsCollection = database.Clients;
    _Result=""
    ClientList = ClientsCollection.find({},{ "_id": 0, "Name": 1, "Firstname": 1 })
    for curClient in ClientList:
        if _Result=="":
            _Result="["
        else:
            _Result+=","

        print(curClient)
        _Result+=json.dumps(curClient)

    if _Result!="":
        _Result+=']'

    return _Result

