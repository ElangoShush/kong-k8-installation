#!/usr/bin/env python3
import os
import json
import logging
from typing import Optional, Dict, Any

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("ts43-issue-auth-code")

# -----------------------
# Config (env fallbacks)
# -----------------------
DEFAULT_KONG_BASE = os.getenv("KONG_BASE_URL", "")
DEFAULT_CLIENT_ID = os.getenv("KONG_CLIENT_ID", "")
DEFAULT_CLIENT_SECRET = os.getenv("KONG_CLIENT_SECRET", "")
DEFAULT_SCOPE = os.getenv("KONG_SCOPE", "")

# For self-signed / NodePort TLS you may want to disable verification.
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() in ("1", "true", "yes")

# HTTP timeouts
REQ_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))

app = FastAPI(title="ts43-issue-auth-code", version="1.0.0")


def get_client_credentials_token(
    kong_base_url: str,
    client_id: str,
    client_secret: str,
    scope: Optional[str] = None,
    verify_tls: bool = True,
    timeout_sec: float = 10.0,
) -> Dict[str, Any]:
    """
    Call Kong OAuth2 plugin token endpoint:
      POST {kong_base_url}/oauth2/token
    Returns dict: { access_token, token_type, expires_in, ... }
    """
    if not kong_base_url:
        raise ValueError("kong_base_url is required")
    if not client_id or not client_secret:
        raise ValueError("client_id and client_secret are required")

    url = kong_base_url.rstrip("/") + "/oauth2/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        data["scope"] = scope

    log.info(f"Requesting token from: {url}")
    try:
        resp = requests.post(url, data=data, timeout=timeout_sec, verify=verify_tls)
        if resp.status_code >= 400:
            log.error("Token request failed: %s %s", resp.status_code, resp.text)
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        payload = resp.json()
        # Basic validation
        if "access_token" not in payload:
            log.error("Token response missing 'access_token': %s", payload)
            raise HTTPException(status_code=502, detail="Invalid token response from Kong")
        return payload
    except requests.RequestException as e:
        log.exception("Token request error")
        raise HTTPException(status_code=502, detail=f"Token request error: {e}")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/v2/issue_auth_code")
async def issue_auth_code(req: Request):
    """
    This endpoint expects (from Kong request-transformer) in the **JSON body**:
      - client_id
      - client_secret
      - scope            (optional)
      - kong_base_url    (your Kong admin/public base that hosts /oauth2/token)
    If not present, falls back to env vars (KONG_CLIENT_ID, etc).

    It returns the token payload from Kong’s /oauth2/token.
    """
    try:
        body = await req.json()
    except Exception:
        body = {}

    # Read from body first (Kong request-transformer adds these), else env
    kong_base = (body.get("kong_base_url") or DEFAULT_KONG_BASE).strip()
    client_id = (body.get("client_id") or DEFAULT_CLIENT_ID).strip()
    client_secret = (body.get("client_secret") or DEFAULT_CLIENT_SECRET).strip()
    scope = (body.get("scope") or DEFAULT_SCOPE).strip() or None

    log.info(f"kong_base: {kong_base}")
    log.info(f"client_id: {client_id}")
    log.info(f"client_secret: {client_secret}")
    log.info(f"scope: {scope}")
    
    
    if not kong_base:
        raise HTTPException(status_code=400, detail="kong_base_url missing (and KONG_BASE_URL not set)")
    if not client_id or not client_secret:
        raise HTTPException(status_code=400, detail="client_id / client_secret missing (and env not set)")

    token = get_client_credentials_token(
        kong_base_url=kong_base,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        verify_tls=VERIFY_TLS,
        timeout_sec=REQ_TIMEOUT,
    )

    # You can extend here to call a downstream `/v2/issue_auth_code` backend with the token if needed.
    # For now, we just return the token payload.
    return JSONResponse(token)


if __name__ == "__main__":
    # Run directly: python3 ts43-issue-auth-code.py
    # Binds to 0.0.0.0:8080 so K8s Service can reach it
    uvicorn.run("ts43-issue-auth-code:app", host="0.0.0.0", port=int(os.getenv("PORT", "8080")), reload=False)
