from flask import Flask

app = Flask(__name__)

import pymongo

mongoclient = pymongo.MongoClient("mongodb://localhost:27017/")
database = mongoclient.TicketsManagement

import ApplicationFlask.Routes
