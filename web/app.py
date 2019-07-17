from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient()
db = client.SimilarityDB
users = db["Users"]


def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


class Register(Resource):
    @staticmethod
    def post():
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'Invalid Username'
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 6
        })

        retJson = {
            "status": 200,
            "msg": "You successfully signed for api access"
        }
        return jsonify(retJson)


def verifyPw(username, password):
    if not UserExist(username):
        return False
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens


class Refill(Resource):
    @staticmethod
    def post():
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        if not UserExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid Username"
            }
            return jsonify(retJson)

        correct_pw = "passwordHacked"
        if not password == correct_pw:
            retJson = {
                "status": 304,
                "msg": "Invalid Admin Password"
            }
            return jsonify(retJson)

        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": countTokens(username) + refill_amount
            }
        })

        retJson = {
            "status": 200,
            "msg": "Refilled Successfully"
        }
        return jsonify(retJson)


class Detect(Resource):
    @staticmethod
    def post():
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if not UserExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid Username"
            }
            return jsonify(retJson)

        correct_pw = verifyPw(username, password)
        if not correct_pw:
            retJson = {
                "status": 302,
                "msg": "Incorrect Password"
            }
            return jsonify(retJson)
        num_tokens = countTokens(username)

        if num_tokens <= 0:
            retJson = {
                "status": 303,
                "msg": "You are Out of tokens,Please Refill!"
            }
            return jsonify(retJson)

        current_token = countTokens(username)
        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": current_token - 1
            }
        })
        bal_tokens = countTokens(username)
        retJson = {
            "status": 200,
            "msg": "Api Called successfully and remember you used one ,Balance:" + str(bal_tokens)
        }
        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Refill, '/refill')
api.add_resource(Detect, '/detect')


if __name__ == "__main__":
    app.run(host='0.0.0.0')