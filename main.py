from functools import wraps

import jwt
import flask_login
from flask_restful import Api, Resource, reqparse, abort
from flask import Flask, session, request, jsonify
from flask_login import LoginManager, login_user, login_required, UserMixin

from flask_session import Session
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'AJDJRJS24$($(#$$33--'  # <--- SECRET_KEY must be set in config to access session
login_manager = LoginManager(app)
auth = HTTPBasicAuth()


@login_manager.user_loader
def load_user(user_id):
    return customers[int(user_id)]


login_manager.init_app(app)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


class Customer_Template():

    def __init__(self, user_id, name, age, gender):
        self.id = int(user_id)
        self.name = name
        self.age = age
        self.gender = gender
        self.is_active = True
        self.is_authenticated = False
        self.token = {}

    def get_id(self):
        return str(self.id)


customers = {
    0: Customer_Template(0, "Rohit", 18, "Male"),
    1: Customer_Template(1, "Mayanka", 18, "Male"),
    2: Customer_Template(2, "Avay", 18, "Male")
}

details = {
    "Rohit": {
        "password": "hello",
        "id": 0,
    },
    "Mayanka": {
        "password": "admin",
        "id": 1,
    }
}


class LogIn(Resource):

    def __init__(self):
        self.password_args = reqparse.RequestParser()
        self.password_args.add_argument("username", type=str, help="Username is required", required=True)
        self.password_args.add_argument("password", type=str, help="Password is required", required=True)

    def post(self):
        args = self.password_args.parse_args()
        username = args["username"]
        password = args["password"]
        if username not in details or details[username]["password"] != password:
            abort(403, message="Incorrect log in details")

        user = customers[details[username]['id']]
        login_user(user)
        user.is_authenticated = True
        user = flask_login.current_user

        result = {
            "name": user.name,
            "age": user.age,
            "gender": user.gender,
            "id": user.id
        }

        session['current_user'] = result
        return session['current_user']


@auth.verify_password
def verify(username, password):
    if not username in details or details[username]['password'] != password:
        return False
    return True


class Customer(Resource):
    @login_required
    @app.route('/customers/<user_id>', methods=['GET'])
    # first method: using sessions
    def get(self, user_id):
        current = None
        if 'current_user' in session:
            if str(session['current_user']['id']) == str(user_id):
                return session['current_user']
            abort(401, message="Unauthorized user!")


# method 2: http auth
class All_customers(Resource):
    @auth.login_required
    def get(self):
        return {"logged_in": "true"}


# method 3: jwt

class All_customers_JWT(Resource):
    def get(self):
        return {"access token": "valid"}


# method 3
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {
                       "message": "Authentication Token is missing!",
                       "data": None,
                       "error": "Unauthorized"
                   }, 401
        try:
            current_user = flask_login.current_user
            # data=jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            # current_user=models.User().get_by_id(data["user_id"])
            if current_user is None:
                return {
                           "message": "Invalid Authentication token!",
                           "data": None,
                           "error": "Unauthorized"
                       }, 401
            if not current_user.is_active:
                abort(403)
        except Exception as e:
            return {
                       "message": "Something went wrong",
                       "data": None,
                       "error": str(e)
                   }, 500

        return f(current_user, *args, **kwargs)

    return decorated


class All_Customers_JWT(Resource):
    def __init__(self):
        self.password_args = reqparse.RequestParser()
        self.password_args.add_argument("username", type=str, help="Username is required", required=True)
        self.password_args.add_argument("password", type=str, help="Password is required", required=True)

    @token_required
    def get(self, token_check):
        return {"access": "approved"}
    # make sure to include token check

    def post(self):
        try:
            data = self.password_args.parse_args()
            if not data:
                return {
                           "message": "Please provide user details",
                           "data": None,
                           "error": "Bad request"
                       }, 400
            # validate input
            # is_validated = validate_email_and_password(data.get('email'), data.get('password'))
            if data['username'] not in details or data['password'] != details[data['username']]['password']:
                return dict(message='Invalid data', data=None), 400
            user_obj = customers[details[data['username']]['id']]
            loggedInUser = Customer_Template(user_obj.id, user_obj.name, user_obj.age, user_obj.gender)
            if loggedInUser:
                try:
                    # token should expire after 24 hrs
                    user_obj.token = jwt.encode(
                        {"user_id": user_obj.id},
                        app.config["SECRET_KEY"],
                        algorithm="HS256"
                    )
                    return {
                        "message": "Successfully fetched auth token",
                        "data": {
                            "id": user_obj.id,
                            "name": user_obj.name,
                            "age": user_obj.age,
                            "gender": user_obj.gender,
                            "token": user_obj.token
                        }
                    }
                except Exception as e:
                    return {
                               "error": "Something went wrong",
                               "message": str(e)
                           }, 500
            return {
                       "message": "Error fetching auth token!, invalid email or password",
                       "data": None,
                       "error": "Unauthorized"
                   }, 404
        except Exception as e:
            return {
                       "message": "Something went wrong!",
                       "error": str(e),
                       "data": None
                   }, 500


api.add_resource(LogIn, '/customers/login')
api.add_resource(Customer, "/customers/<int:user_id>")
api.add_resource(All_customers, '/customers/')
api.add_resource(All_Customers_JWT, '/users/')
if __name__ == '__main__':
    app.run(debug=True)
