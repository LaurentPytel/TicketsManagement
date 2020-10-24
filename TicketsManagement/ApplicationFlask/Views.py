from flask import Flask
from ApplicationFlask import app

@app.route('/')
@app.route('/home')
def home():
    return "Hello Flask!"