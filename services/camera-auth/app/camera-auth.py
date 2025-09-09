#!/usr/bin/env python3
import os
import logging
import time
import base64
import json
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

import requests
import redis
from fastapi import FastAPI, Response, Form, HTTPException, Header
from fastapi.responses import JSONResponse

# --- Configuration and Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("camera-auth")
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() in ("1", "true", "yes")
REQ_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
EXTERNAL_AUTH_URL = os.environ["EXTERNAL_AUTH_URL"].strip()
KONG_INTERNAL_BASE = os.environ["KONG_INTERNAL_OAUTH_URL"].strip()


# --- Redis Configuration ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_TTL = int(os.getenv("REDIS_TTL", 300))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

# --- Redis Client ---
_redis_client = None

def get_redis_client():
    """Initializes and returns a Redis client, reusing an existing connection."""
    global _redis_client
    if _redis_client is None:
        try:
            log.info(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")
            _redis_client = redis.StrictRedis(
                host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
                decode_responses=True, socket_connect_timeout=2
            )
            _redis_client.ping()
            log.info("Successfully connected to Redis.")
        except redis.exceptions.AuthenticationError:
            log.error("Redis authentication failed. Check the REDIS_PASSWORD environment variable.")
            _redis_client = None; raise
        except redis.exceptions.ConnectionError as e:
            log.error(f"Could not connect to Redis: {e}")
            _redis_client = None; raise
    return _redis_client


# --- Authorization Code Logic (No changes here) ---
def generate_auth_code(login_hint: str) -> str:
    timestamp = str(int(time.time()))
    internal_token = f"{login_hint}:{timestamp}"
    raw_data = f"token={internal_token}&login_hint={login_hint}"
    auth_code = base64.urlsafe_b64encode(raw_data.encode()).decode()
    log.info(f"Generated auth code. Decoded payload will be: '{raw_data}'")
    return auth_code

def store_auth_code(auth_code: str, msisdn: str, provision_key: str, client_id: str, client_secret: str) -> bool:
    try:
        redis_client = get_redis_client()
        redis_key = f"auth_code:{auth_code}"
        redis_value = json.dumps({
            "msisdn": msisdn, "provision_key": provision_key,
            "client_id": client_id, "client_secret": client_secret
        })
        redis_client.setex(redis_key, REDIS_TTL, redis_value)
        log.info(f"Successfully stored auth context in Redis for client_id: {client_id}.")
        return True
    except redis.RedisError as e:
        log.error(f"Redis error while storing auth code: {e}")
        return False

def validate_and_get_data_from_code(auth_code: str) -> dict | None:
    if not auth_code: return None
    try:
        redis_client = get_redis_client()
        redis_key = f"auth_code:{auth_code}"
        stored_data_str = redis_client.get(redis_key)
        if stored_data_str:
            log.info("Auth code found in Redis. Deleting it to prevent reuse.")
            redis_client.delete(redis_key)
            return json.loads(stored_data_str)
        else:
            log.warning(f"Auth code not found in Redis: {auth_code}")
            return None
    except redis.RedisError as e:
        log.error(f"Redis error while validating auth code: {e}")
        return None
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse JSON from Redis for key {redis_key}: {e}. Value was: {stored_data_str}")
        return None

app = FastAPI(
    title="Camera Authorizer Service",
    description="Orchestrates external authentication and token exchange with explicit paths.",
    version="1.6.0"
)

@app.get("/healthz")
def healthz():
    try:
        get_redis_client().ping()
        return {"status": "ok", "redis_connection": "ok"}
    except Exception as e:
        log.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service is unhealthy: {str(e)}")

@app.post("/authorizer")
def handle_authorization(
    # ... form parameters are the same ...
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str = Form(...),
    provision_key: str = Form(...),
    login_hint: str = Form(...),
    response_type: str = Form(...),
    scope: str = Form(None),
    authenticated_userid: str = Form(...),
    identifier: str = Form(...),
    carrierName: str = Form(...),
    customerName: str = Form(...),
    ipAddress: str = Form(...),
    grant_type: str = Form(None)
):
    try:
        log.info(f"Received authorization request for login_hint (msisdn): {login_hint}")
        auth_params = { "identifier": identifier, "carrierName": carrierName, "customerName": customerName, "msisdn": login_hint, "ipAddress": ipAddress }
        external_resp = requests.get(EXTERNAL_AUTH_URL, params=auth_params, timeout=REQ_TIMEOUT, verify=VERIFY_TLS)
        
        if external_resp.status_code != 200:
            log.warning(f"External auth failed with status {external_resp.status_code}: {external_resp.text}")
            try: error_detail = external_resp.json()
            except requests.exceptions.JSONDecodeError: error_detail = {"detail": external_resp.text or "Unknown error"}
            raise HTTPException(status_code=external_resp.status_code, detail=error_detail.get("detail", error_detail))
            
        log.info("External authentication successful.")
        custom_auth_code = generate_auth_code(login_hint)
        
        if not store_auth_code(custom_auth_code, login_hint, provision_key, client_id, client_secret):
            raise HTTPException(status_code=503, detail="Failed to store authorization context. Please try again later.")
            
        final_redirect_uri = f"{redirect_uri}?code={custom_auth_code}"
        log.info(f"Successfully generated code. Returning redirect URI: {final_redirect_uri}")
        return JSONResponse(content={"redirect_uri": final_redirect_uri})
        
    except requests.RequestException as e:
        log.exception("HTTP request error during authorization flow")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except HTTPException: raise
    except Exception as e:
        log.exception("An unexpected error occurred during authorization")
        raise HTTPException(status_code=500, detail="An internal server error occurred")

@app.post("/token")
def handle_custom_token_exchange(
    code: str = Header(...)
):
    try:
        log.info(f"Received custom token exchange request.")
        auth_data = validate_and_get_data_from_code(code)
        if not auth_data:
            raise HTTPException(status_code=400, detail="Invalid, expired, or previously used code.")
        
        client_id = auth_data.get("client_id")
        client_secret = auth_data.get("client_secret")

        if not client_id or not client_secret:
            raise HTTPException(status_code=500, detail="Stored authorization context is incomplete.")

        log.info(f"Auth code validated successfully for client_id: {client_id}")

        kong_token_url = KONG_INTERNAL_BASE.rstrip("/") + "/oauth2/token"
        kong_payload = { "grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret }
        
        log.info(f"Calling Kong's internal token endpoint: {kong_token_url}")
        kong_resp = requests.post(kong_token_url, data=kong_payload, timeout=REQ_TIMEOUT, verify=VERIFY_TLS)

        log.info(f"Received response from Kong token endpoint. Status: {kong_resp.status_code}")
        try: response_content = kong_resp.json()
        except requests.exceptions.JSONDecodeError: response_content = kong_resp.text

        return JSONResponse(status_code=kong_resp.status_code, content=response_content)

    except HTTPException: raise
    except requests.RequestException as e:
        log.exception("HTTP request error during token exchange")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except Exception as e:
        log.exception("An unexpected error occurred during token exchange")
        raise HTTPException(status_code=500, detail="An internal server error occurred")

