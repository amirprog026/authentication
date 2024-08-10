from flask import Flask, request, jsonify,redirect
import memcache,random,logging
import hashlib,datetime
URLPREFIX='https://testing.dbcloud.ir/wp-json/custom/v1'
WP_SITE="https://testing.dbcloud.ir/"
def generate_sms_token():
    return random.randint(10000,99999)
def send_SMS():
    pass
app = Flask(__name__)
mc = memcache.Client(['127.0.0.1:11211'], debug=0)

import requests

def wpregister(username, password, email):
    url = URLPREFIX+"/register"
    payload = {
        "username": username,
        "password": password,
        "email": email
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        return response.json()
def wplogin(username, password)->str:
    url = URLPREFIX+"/login"
    payload = {
        "username": username,
        "password": password,
        
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return dict(response.json())
    else:
        return None
    


def send_auth_hook_wp():
    pass
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = hash_password(password)
    if mc.get(username):
        return jsonify({"error": "User already exists"}), 400

    mc.set(username, hashed_password)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = hash_password(password)

    response_from_wp=wplogin(username,password)
    if response_from_wp is None:
        logging.critical(f"{datetime.datetime.now()} Wrong credential login for {username}")
        return jsonify({"error": "Invalid credentials"}), 401
    token = response_from_wp["token"]
    
    logging.info(f"{datetime.datetime.now()} Successfull login for {username}")
    return redirect(f"{WP_SITE}/?{token}")


if __name__ == '__main__':
    new_user = wpregister("new_username", "new_password", "new_email@example.com")
    print(new_user)
