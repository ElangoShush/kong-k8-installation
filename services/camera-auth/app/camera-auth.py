#!/usr/bin/env python3
import os
import logging
import time
import base64
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

import requests
import redis
from fastapi import FastAPI, Response, Form, HTTPException
from fastapi.responses import JSONResponse

# --- Configuration and Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("camera-auth")
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() in ("1", "true", "yes")
REQ_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
EXTERNAL_AUTH_URL = os.environ["EXTERNAL_AUTH_URL"].strip()

# --- Redis Configuration ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_TTL = int(os.getenv("REDIS_TTL", 300))
# This is the crucial line that reads the password from the environment
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

# --- Redis Client ---
_redis_client = None

def get_redis_client():
    """Initializes and returns a Redis client, reusing an existing connection."""
    global _redis_client
    if _redis_client is None:
        try:
            log.info(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")
            # The password from the environment is passed to the Redis client here
            _redis_client = redis.StrictRedis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=2
            )
            _redis_client.ping()
            log.info("Successfully connected to Redis.")
        except redis.exceptions.AuthenticationError:
            log.error("Redis authentication failed. Check the REDIS_PASSWORD environment variable.")
            _redis_client = None
            raise
        except redis.exceptions.ConnectionError as e:
            log.error(f"Could not connect to Redis: {e}")
            _redis_client = None
            raise
    return _redis_client


# --- NEW: Authorization Code Logic from Lambda ---
def generate_auth_code(login_hint: str) -> str:
    """
    Generate a time-stamped, base64-encoded auth code.
    This makes the code temporary and ties it to the user.
    """
    timestamp = str(int(time.time()))
    raw_data = f"{login_hint}:{timestamp}"
    auth_code = base64.urlsafe_b64encode(raw_data.encode()).decode()
    log.info(f"Generated auth code for login_hint: {login_hint}")
    return auth_code

def store_auth_code(msisdn: str, auth_code: str) -> bool:
    """Store the auth code in Redis with a specific TTL."""
    try:
        redis_client = get_redis_client()
        if not redis_client:
            log.error("Cannot store auth code, Redis client is not available.")
            return False

        # The key is the auth code itself, value is the user identifier (msisdn)
        redis_key = f"auth_code:{auth_code}"
        redis_client.setex(redis_key, REDIS_TTL, msisdn)
        log.info(f"Successfully stored auth code in Redis with TTL {REDIS_TTL}s.")
        return True
    except redis.RedisError as e:
        log.error(f"Redis error while storing auth code: {e}")
        return False


app = FastAPI(
    title="Camera Authorizer Service",
    description="Orchestrates external authentication and generates custom authorization codes.",
    version="1.2.0"
)

@app.get("/healthz")
def healthz():
    """Health check endpoint."""
    try:
        redis_client = get_redis_client()
        if redis_client:
            redis_client.ping()
            return {"status": "ok", "redis_connection": "ok"}
        else:
             return {"status": "ok", "redis_connection": "disconnected"}
    except Exception as e:
        log.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service is unhealthy: {str(e)}")


@app.post("/")
def handle_authorization(
    response: Response,
    response_type: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(None),
    provision_key: str = Form(...),
    authenticated_userid: str = Form(...),
    login_hint: str = Form(...),
    identifier: str = Form(...),
    carrierName: str = Form(...),
    customerName: str = Form(...),
    ipAddress: str = Form(...),
    grant_type: str = Form(None)
):
    # This logic does not need to change
    try:
        log.info(f"Received authorization request for login_hint (msisdn): {login_hint}")
         # --- Step 1: Call External Authentication API ---
        auth_params = {
            "identifier": identifier,
            "carrierName": carrierName,
            "customerName": customerName,
            "msisdn": login_hint,
            "ipAddress": ipAddress
        }
        log.info(f"Calling external auth API: {EXTERNAL_AUTH_URL} with params: {auth_params}")
        external_resp = requests.get(
            EXTERNAL_AUTH_URL,
            params=auth_params,
            timeout=REQ_TIMEOUT,
            verify=VERIFY_TLS
        )
        if external_resp.status_code != 200:
            log.warning(f"External auth failed with status {external_resp.status_code}: {external_resp.text}")
            try:
                error_detail = external_resp.json()
            except requests.exceptions.JSONDecodeError:
                error_detail = {"detail": external_resp.text or "Unknown error from external service"}
            raise HTTPException(status_code=external_resp.status_code, detail=error_detail.get("detail", error_detail))
        log.info("External authentication successful.")
        custom_auth_code = generate_auth_code(login_hint)
        if not store_auth_code(login_hint, custom_auth_code):
            raise HTTPException(status_code=503, detail="Failed to store authorization code. Please try again later.")
        final_redirect_uri = f"{redirect_uri}?code={custom_auth_code}"
        log.info(f"Successfully generated code. Returning redirect URI: {final_redirect_uri}")
        return JSONResponse(content={"redirect_uri": final_redirect_uri})
    except requests.RequestException as e:
        log.exception("HTTP request error during authorization flow")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except HTTPException:
        raise
    except Exception as e:
        log.exception("An unexpected error occurred during authorization")
        raise HTTPException(status_code=500, detail="An internal server error occurred")

def generate_auth_code(login_hint: str) -> str:
    timestamp = str(int(time.time()))
    raw_data = f"{login_hint}:{timestamp}"
    auth_code = base64.urlsafe_b64encode(raw_data.encode()).decode()
    log.info(f"Generated auth code for login_hint: {login_hint}")
    return auth_code

def store_auth_code(msisdn: str, auth_code: str) -> bool:
    try:
        redis_client = get_redis_client()
        if not redis_client:
            log.error("Cannot store auth code, Redis client is not available.")
            return False
        redis_key = f"auth_code:{auth_code}"
        redis_client.setex(redis_key, REDIS_TTL, msisdn)
        log.info(f"Successfully stored auth code in Redis with TTL {REDIS_TTL}s.")
        return True
    except redis.RedisError as e:
        log.error(f"Redis error while storing auth code: {e}")
        return False