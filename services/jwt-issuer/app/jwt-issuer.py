# FILE: app.py

import jwt
import os
import time
import requests
from fastapi import FastAPI, Header, HTTPException, Response
from typing import Optional

app = FastAPI()

# --- Configuration ---
KONG_ADMIN_URL = os.environ.get("KONG_ADMIN_URL")
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = 3600

# A simple in-memory cache to avoid calling the Kong Admin API on every request
secret_cache = {}

def get_secret_for_consumer(username: str) -> Optional[str]:
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
        response = requests.get(url, timeout=5)
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

@app.get("/")
def issue_jwt(
    x_consumer_username: Optional[str] = Header(None),
    x_login_hint: Optional[str] = Header(None)
):
    if not x_consumer_username or not x_login_hint:
        raise HTTPException(status_code=400, detail="Missing required headers from Kong Gateway")

    jwt_secret = get_secret_for_consumer(x_consumer_username)

    if not jwt_secret:
        raise HTTPException(status_code=500, detail=f"Could not find a valid secret for consumer '{x_consumer_username}'")

    current_time = int(time.time())
    
    payload = {
        "iss": x_consumer_username,
        "login_hint": x_login_hint,
        "iat": current_time,
        "exp": current_time + TOKEN_LIFETIME
    }

    signed_jwt = jwt.encode(payload, jwt_secret, algorithm=JWT_ALGORITHM)
    
    return {"jwt": signed_jwt}

@app.get("/healthz")
def healthz():
    return Response(content="OK", status_code=200)

