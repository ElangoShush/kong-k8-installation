# FILE: app.py

import jwt
import os
import time
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Configuration ---
KONG_ADMIN_URL = os.environ.get("KONG_ADMIN_URL")
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = 3600

# A simple in-memory cache to avoid calling the Kong Admin API on every request
secret_cache = {}

def get_secret_for_consumer(username):
    """
    Fetches a consumer's JWT secret from the Kong Admin API, with caching.
    """
    if username in secret_cache:
        return secret_cache[username]

    if not KONG_ADMIN_URL:
        print("ERROR: KONG_ADMIN_URL environment variable is not set.")
        return None

    try:
        url = f"{KONG_ADMIN_URL}/consumers/{username}/jwt"
        response = requests.get(url, timeout=5) # Added timeout
        response.raise_for_status()
        
        data = response.json().get("data", [])
        if data:
            secret = data[0].get("secret")
            if secret:
                secret_cache[username] = secret
                return secret
            
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch secret for consumer '{username}': {e}")
        return None
    
    print(f"WARN: No JWT secret found for consumer '{username}'")
    return None

@app.route("/")
def issue_jwt():
    consumer_username = request.headers.get("X-Consumer-Username")
    login_hint = request.headers.get("X-Login-Hint")

    if not consumer_username or not login_hint:
        return jsonify({"error": "Missing required headers from Kong Gateway"}), 400

    jwt_secret = get_secret_for_consumer(consumer_username)

    if not jwt_secret:
        return jsonify({"error": f"Could not find a valid secret for consumer '{consumer_username}'"}), 500

    current_time = int(time.time())
    
    # FIXED: Replaced "..." with proper 'iat' and 'exp' claims.
    payload = {
        "iss": consumer_username,
        "login_hint": login_hint,
        "iat": current_time,
        "exp": current_time + TOKEN_LIFETIME
    }

    signed_jwt = jwt.encode(payload, jwt_secret, algorithm=JWT_ALGORITHM)
    
    return jsonify({"jwt": signed_jwt})

@app.route("/healthz")
def healthz():
    return "OK", 200
