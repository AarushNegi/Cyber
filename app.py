from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["users"]
users_collection = db["mails"]


# SIGNUP ROUTE
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json

    username = data["username"]
    password = data["password"]

    users_collection.insert_one({
        "username": username,
        "password": password
    })

    return jsonify({
        "success": True,
        "message": "User added"
    })


# SIGNIN ROUTE
@app.route("/signin", methods=["POST"])
def signin():
    data = request.json

    username = data["username"]
    password = data["password"]

    user = users_collection.find_one({
        "username": username,
        "password": password
    })

    if user:
        return jsonify({
            "success": True,
            "message": "Login successful"
        })
    else:
        return jsonify({
            "success": False,
            "message": "Invalid credentials"
        })


# RUN SERVER
if __name__ == "__main__":
    app.run(debug=True)