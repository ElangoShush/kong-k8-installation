#!/usr/bin/env python3
import os
import logging
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

import requests
from fastapi import FastAPI, Response, Form, HTTPException
from fastapi.responses import JSONResponse

# -----------------------
# Configuration & Logging
# -----------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("camera-auth")

# For self-signed certs in-cluster, Currently i set to false, because KONG use Self Signed Cert .
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() in ("1", "true", "yes")

# HTTP timeouts
REQ_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))

# In-cluster Kong proxy service URL for making the internal OAuth2 call
KONG_INTERNAL_BASE = os.getenv(
    "KONG_INTERNAL_OAUTH_URL",
    "https://kong-kong-proxy.kong.svc.cluster.local:443"
).strip()

# URL for the external service that validates the login_hint
EXTERNAL_AUTH_URL = os.getenv(
    "EXTERNAL_AUTH_URL",
    "http://34.54.169.57/v0/authenticate_user"
).strip()


app = FastAPI(
    title="Camera Authorizer Service",
    description="Orchestrates external authentication and the Kong OAuth2 flow.",
    version="1.0.0"
)


# --- Health Check Endpoint ---
@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# --- Helper Functions ---
def parse_code_from_uri(uri: str) -> str | None:
    """Extracts the 'code' query parameter from a URI."""
    try:
        parsed_url = urlparse(uri)
        query_params = parse_qs(parsed_url.query)
        return query_params.get("code", [None])[0]
    except Exception as e:
        log.error(f"Failed to parse code from URI: {uri}. Error: {e}")
        return None

# --- NEW HELPER FUNCTION TO PARSE LOGIN HINT ---
def parse_login_hint(hint: str) -> Dict[str, str]:
    try:
        # parse_qs returns a dict where values are lists
        parsed_data = parse_qs(hint)
        if not parsed_data:
            raise ValueError("login_hint is empty or in an invalid format.")
            
        # We expect single values, so we extract the first element of each list
        data = {k: v[0] for k, v in parsed_data.items()}
        
        # Validate that all required keys are present
        required_keys = ["msisdn", "identifier", "carrierName", "customerName", "ipAddress"]
        missing_keys = [key for key in required_keys if key not in data]
        if missing_keys:
            raise ValueError(f"Missing required parameters in login_hint: {', '.join(missing_keys)}")
            
        return data
    except Exception as e:
        log.error(f"Failed to parse login_hint: '{hint}'. Error: {e}")
        # Re-raise as ValueError to be caught by the endpoint handler
        raise ValueError(f"Invalid login_hint format. {e}")


# --- Main Authorization Endpoint (MODIFIED) ---
@app.post("/")
def handle_authorization(
    response: Response,
    # Use Form() to extract data from 'application/x-www-form-urlencoded'
    login_hint: str = Form(...),
    response_type: str = Form("code"),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(None),
    provision_key: str = Form(...),
    authenticated_userid: str = Form(...)
):
    log.info(f"Received authorization request with login_hint: {login_hint}")

    # --- Step 1: Parse login_hint and Call External Authentication API ---
    try:
        # Dynamically get params from the login_hint string
        parsed_hint_data = parse_login_hint(login_hint)
        # Build the params for the external auth call
        auth_params = {
            "identifier": parsed_hint_data["identifier"],
            "carrierName": parsed_hint_data["carrierName"],
            "customerName": parsed_hint_data["customerName"],
            "msisdn": parsed_hint_data["msisdn"],
            "ipAddress": parsed_hint_data["ipAddress"]
        }
    except ValueError as e:
        # If parsing fails (e.g., missing keys), return a 400 Bad Request
        raise HTTPException(status_code=400, detail=str(e))
    try:
        log.info(f"Calling external auth API: {EXTERNAL_AUTH_URL} with params: {auth_params}")
        external_resp = requests.get(
            EXTERNAL_AUTH_URL,
            params=auth_params,
            timeout=REQ_TIMEOUT,
            verify=VERIFY_TLS
        )
        if external_resp.status_code != 200:
            log.warning(f"External auth failed with status {external_resp.status_code}: {external_resp.text}")
            raise HTTPException(status_code=401, detail="External user authentication failed")

        log.info("External authentication successful.")

        # --- Step 2: Call Kong's internal /oauth2/authorize endpoint ---
        kong_authorize_url = KONG_INTERNAL_BASE.rstrip("/") + "/oauth2/authorize"
        kong_payload = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "provision_key": provision_key,
            "authenticated_userid": authenticated_userid,
            # Pass the original, full login_hint to Kong if needed
            "login_hint": login_hint 
        }
        kong_payload = {k: v for k, v in kong_payload.items() if v is not None}

        log.info(f"Calling Kong's internal authorize endpoint: {kong_authorize_url}")
        kong_resp = requests.post(
            kong_authorize_url,
            data=kong_payload,
            timeout=REQ_TIMEOUT,
            verify=VERIFY_TLS
        )

        if kong_resp.status_code >= 400:
            log.error(f"Kong returned an error. Status: {kong_resp.status_code}. Response: {kong_resp.text}")
            return JSONResponse(status_code=kong_resp.status_code, content={"error_detail": kong_resp.text})

        # --- Step 3: Success. Extract code and return redirect URI ---
        response_data = kong_resp.json()
        redirect_uri_from_kong = response_data.get("redirect_uri")
        if not redirect_uri_from_kong or not parse_code_from_uri(redirect_uri_from_kong):
            log.error(f"Kong response is missing or malformed: {response_data}")
            raise HTTPException(status_code=502, detail="Invalid response from Kong authorize endpoint")

        log.info("Successfully obtained auth code from Kong.")
        return JSONResponse(content={"redirect_uri": redirect_uri_from_kong})

    except requests.RequestException as e:
        log.exception("HTTP request error during authorization flow")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except Exception as e:
        log.exception("An unexpected error occurred")
        raise HTTPException(status_code=500, detail="An internal server error occurred")