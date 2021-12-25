import json
from flask.json import jsonify
from flask import Flask, request, session
from functools import wraps
import jwt
from requests.models import Response
from http import HTTPStatus
import requests
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'


class Service:
    services_count = 0

    def __init__(self, name, address, port):
        self.name = name
        self.url = f"http://{address}:{port}"
        Service.services_count += 1
        self.id = Service.services_count


class ServiceState:
    def __init__(self):
        self.state = "c"
        self.num_of_failures = 0
        self.last_attempt = 0


def decode_token(token):

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms='HS256')
        return payload["sub"]

    except jwt.ExpiredSignatureError:
        return "your token is expired!"

    except jwt.InvalidTokenError:
        return "first of all, login!"


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({"message": "login first"}), HTTPStatus.UNAUTHORIZED
        try:
            username = decode_token(token)

        except Exception as e:
            return jsonify(str(e)), HTTPStatus.UNAUTHORIZED

        return f(username, *args, **kwargs)

    return decorator


account_service = Service("Account Service", "127.0.0.1", 8000)


@app.route("/")
def home():
    return 'Wellcome'


@app.route('/signup/<role>', methods=['POST'])
def signup(role):
    json = request.json
    try:
        password = json.pop('password', None)

    except:
        return jsonify('Password?'), HTTPStatus.BAD_REQUEST

    json['hashed_pass'] = generate_password_hash(password)
    response = requests.post(f"127.0.0.1:8000/create_user/{role}", timeout=0.75, json=json)
    #response = circuit_breaker.send_request(requests.post, account_service, f"/create_user/{role}", json=json)
    #response = func(uri, timeout=0.75, *args, **kwargs)
    return response.content, response.status_code, response.headers.items()


@app.route('/signin/<role>', methods=['POST'])
def signin(role):
    json = request.json
    try:
        id = json.get('national_id')
    except:
        return jsonify("national id?"), HTTPStatus.BAD_REQUEST

    try:
        password = json.get('password')
    except:
        return jsonify("Password?"), HTTPStatus.BAD_REQUEST

    response = requests.get(f"127.0.0.1:8000/user/{role}/{id}", timeout=0.75, json=json)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()

    user = response.json()['user']
    expiration_time = (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()
    if check_password_hash(user['hashed_pass'], password):
        payload = {
            'sub': id,
            'exp': expiration_time
        }
        token = jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
        session["role"] = role
        return jsonify("Login Successful", jwt=token), HTTPStatus.OK
    return jsonify('Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route('/admin-signup', methods=['POST'])
def admin_signup():
    json = request.json
    try:
        password = json.pop('password', None)

    except:
        return jsonify('Password?'), HTTPStatus.BAD_REQUEST

    json['hashed_pass'] = generate_password_hash(password)
    response = requests.post(f"127.0.0.1:8000/create_admin", timeout=0.75, json=json)
    return response.content, response.status_code, response.headers.items()


@app.route('/admin-signin', methods=['POST'])
def admin_signin():

    json = request.json
    try:
        username = json.get('username')
    except:
        return jsonify(message="username?"), HTTPStatus.BAD_REQUEST

    try:
        password = json.get('password')
    except:
        return jsonify("Password?"), HTTPStatus.BAD_REQUEST

    response = requests.get(f"127.0.0.1:8000/admin/{username}", timeout=0.75, json=json)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()

    user = response.json()['user']
    expiration_time = (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()
    if check_password_hash(user['hashed_pass'], password):
        payload = {
            'sub': username,
            'exp': expiration_time
        }
        token = jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
        return jsonify("Login Successful", jwt=token), HTTPStatus.OK
    return jsonify('Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route('/patients', methods=['GET'])
@token_required
def get_patients(username):
    response = requests.get(f"127.0.0.1:8000/show_patients/{username}", timeout=0.75, json=json)
    return response.content, response.status_code, response.headers.items()


@app.route('/doctors', methods=['GET'])
@token_required
def get_doctors(username):
    response = requests.get(f"127.0.0.1:8000/show_doctors/{username}", timeout=0.75, json=json)
    return response.content, response.status_code, response.headers.items()


@app.route("/profile")
@token_required
def user_profile(username):
    data = {
        "username": username,
        'role': session["role"]
    }
    response = requests.get(f"127.0.0.1:8000/user_profile/{data}", timeout=0.75, json=json)
    return response.content, response.status_code, response.headers.items()


@app.route("/profile-admin")
@token_required
def admin_profile(username):
    response = requests.get(f"127.0.0.1:8000/admin_profile/{username}", timeout=0.75, json=json)
    return response.content, response.status_code, response.headers.items()


def append_profile_to_data(data, role, is_admin=False):
    id = data[f"{role}_id"]
    response_user = requests.get(f"127.0.0.1:8000/user/{role}/{id}", timeout=0.75, json=json)
    if response_user.status_code != HTTPStatus.OK:
        return response_user.content, response_user.status_code, response_user.headers.items()
    user_detected = response_user.json()["user"]

    if is_admin:
        keys = ['national_id', 'name']
    else:
        keys = ['name']

    your_dict = {key: user_detected[key] for key in keys}
    your_dict["role"] = role
    data[f"{role}_profile"] = your_dict


@app.route('/daily', methods=['GET'])
@token_required
def show_stats_admin(username):
    response = requests.get(f"127.0.0.1:8000/admin/{username}", timeout=0.75, json=json)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()

    responses = {}

    patient_response = requests.get(f"127.0.0.1:8000/patients/stats", timeout=0.75, json=json)
    if patient_response.status_code != HTTPStatus.OK:
        return patient_response.content, patient_response.status_code, patient_response.headers.items()
    responses["patients count"] = len(patient_response.json())

    doctor_response = requests.get(f"127.0.0.1:8000/doctors/stats", timeout=0.75, json=json)
    if doctor_response.status_code != HTTPStatus.OK:
        return doctor_response.content, doctor_response.status_code, doctor_response.headers.items()
    responses["doctors count"] = len(doctor_response.json())

    final_response = Response()
    final_response._content = json.dumps(responses).encode("utf-8")
    return final_response.content, final_response.status_code, final_response.headers.items()


if __name__ == "__main__":
    app.run(port=5000, host="127.0.0.1", debug=True)
