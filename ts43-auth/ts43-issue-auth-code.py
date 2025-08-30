# file: kong_client_credentials.py
import os
import json
import requests
import logging
from typing import Optional, Dict

logging.basicConfig(level=logging.INFO)  # Or DEBUG for more verbose logging
logger = logging.getLogger(__name__)

class KongOAuth2Error(RuntimeError):
    pass

def get_client_credentials_token(
    kong_base_url: str,
    client_id: str,
    client_secret: str,
    scope: Optional[str] = None,
    verify_tls: bool = False,       # set True if you’ve got a valid cert/CA
    timeout_sec: int = 10,
) -> Dict[str, str]:
    """
    Request a token from Kong's /oauth2/token (OAuth2 plugin).
    Returns dict with access_token, token_type, expires_in.
    """
    url = kong_base_url.rstrip("/") + "/oauth2/token"
    logger.info(f"URL: {url}")
    logger.info(f"client_id: {client_id}")
    logger.info(f"client_secret: {client_secret}")
    logger.info(f"scope: {scope}")
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        data["scope"] = scope

    try:
        resp = requests.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=timeout_sec,
            verify=verify_tls,
        )
    except requests.RequestException as e:
        raise KongOAuth2Error(f"Network error contacting {url}: {e}") from e

    logger.info(f"resp: {resp}")
    req_id = resp.headers.get("X-Kong-Request-Id") or resp.headers.get("x-kong-request-id")

    # Raise helpful errors
    if resp.status_code >= 400:
        msg = f"Kong token endpoint error HTTP {resp.status_code}"
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:500]}
        detail = body.get("error_description") or body.get("error") or body
        raise KongOAuth2Error(f"{msg}. detail={detail} request_id={req_id}")

    try:
        js = resp.json()
    except Exception:
        raise KongOAuth2Error(f"Non-JSON response from token endpoint: {resp.text[:500]} request_id={req_id}")

    token = js.get("access_token") or js.get("accessToken")
    if not token:
        raise KongOAuth2Error(f"No access_token in response: {js} request_id={req_id}")

    return {
        "access_token": token,
        "token_type": js.get("token_type", "bearer"),
        "expires_in": str(js.get("expires_in", "")),
    }

def call_ts43_issue_auth_code_with_token(
    kong_base_url: str,
    access_token: str,
    verify_tls: bool = False,
    timeout_sec: int = 10,
):
    """
    Example protected call using the bearer token.
    Adjust JSON/body to what your upstream expects.
    """
    url = kong_base_url.rstrip("/") + "/v2/issue_auth_code"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    resp = requests.post(url, headers=headers, json={}, timeout=timeout_sec, verify=verify_tls)
    req_id = resp.headers.get("X-Kong-Request-Id") or resp.headers.get("x-kong-request-id")
    try:
        body = resp.json()
    except Exception:
        body = {"raw": resp.text[:500]}
    return resp.status_code, body, req_id

if __name__ == "__main__":
    # Defaults for your current setup
    KONG = os.getenv("KONG_BASE_URL")
    CLIENT_ID = os.getenv("KONG_CLIENT_ID")
    CLIENT_SECRET = os.getenv("KONG_CLIENT_SECRET")
    SCOPE = os.getenv("KONG_SCOPE")

    # For your NodePort 32443 with self-signed cert, keep verify_tls=False
    token_info = get_client_credentials_token(KONG, CLIENT_ID, CLIENT_SECRET, scope=SCOPE, verify_tls=False)
    print("token_info:", json.dumps(token_info, indent=2))

    # status, body, req_id = call_ts43_issue_auth_code_with_token(KONG, token_info["access_token"], verify_tls=False)
    # print("issue_auth_code:", status, json.dumps(body, indent=2), "request_id:", req_id)
