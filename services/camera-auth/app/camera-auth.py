import httpx
from fastapi import FastAPI, HTTPException, Response, Form
import logging
from urllib.parse import urlparse, parse_qs
import json

# --- Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FastAPI Application ---
app = FastAPI(
    title="Camera Authorizer Service",
    description="Orchestrates external authentication and the Kong OAuth2 flow.",
    version="1.0.0"
)

# --- Health Check Endpoint ---
@app.get("/healthz")
def health_check():
    return {"status": "ok"}

# --- Helper Function ---
def parse_code_from_uri(uri: str) -> str | None:
    try:
        parsed_url = urlparse(uri)
        query_params = parse_qs(parsed_url.query)
        return query_params.get("code", [None])[0]
    except Exception as e:
        logger.error(f"Failed to parse code from URI: {uri}. Error: {e}")
        return None

# --- Main Authorization Endpoint ---
@app.post("/")
async def handle_authorization(
    response: Response,
    login_hint: str = Form(...),
    response_type: str = Form("code"),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(None),
    provision_key: str = Form(...),
    authenticated_userid: str = Form(...)
):
    logger.info(f"Received authorization request for login_hint: {login_hint}")

    # Step 1: Call External Authentication API
    external_api_url = "http://34.54.1L9.57/v0/authenticate_user"
    params = {
        "identifier": "ABC12345",
        "carrierName": "lab",
        "customerName": "Bank1",
        "msisdn": login_hint,
        "ipAddress": "192.168.0.1"
    }

    # --- THIS IS THE FIX ---
    # Configure TLS verification when creating the client, not in the .post() call.
    try:
        async with httpx.AsyncClient(verify=False) as client:
            logger.info(f"Calling external auth API: {external_api_url} with params: {params}")
            external_response = await client.get(external_api_url, params=params)

            if external_response.status_code != 200:
                logger.warning(f"External auth failed with status: {external_response.status_code}. Response: {external_response.text}")
                raise HTTPException(status_code=401, detail="External user authentication failed")

            logger.info("External authentication successful.")

            # Step 2: Call Kong's internal /oauth2/authorize endpoint
            kong_proxy_url = "https://kong-kong-proxy.kong.svc.cluster.local:8443/oauth2/authorize"
            kong_payload = {
                "response_type": response_type,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "provision_key": provision_key,
                "authenticated_userid": authenticated_userid,
                "login_hint": login_hint
            }
            kong_payload = {k: v for k, v in kong_payload.items() if v is not None}

            logger.info(f"Calling Kong's internal authorize endpoint with payload: {kong_payload}")
            # The 'verify=False' argument is now part of the AsyncClient() initialization above.
            kong_auth_response = await client.post(kong_proxy_url, data=kong_payload)

            if kong_auth_response.status_code >= 400:
                logger.error(f"Kong returned an error. Status: {kong_auth_response.status_code}. Response: {kong_auth_response.text}")
                kong_auth_response.raise_for_status()

            response_data = kong_auth_response.json()
            redirect_uri_from_kong = response_data.get("redirect_uri")
            if not redirect_uri_from_kong:
                logger.error(f"Kong response is missing redirect_uri. Full response: {response_data}")
                raise HTTPException(status_code=500, detail="Kong response missing redirect_uri")

            auth_code = parse_code_from_uri(redirect_uri_from_kong)
            if not auth_code:
                logger.error(f"Could not parse auth code from redirect_uri: {redirect_uri_from_kong}")
                raise HTTPException(status_code=500, detail="Could not parse auth code from redirect_uri")

            logger.info(f"Successfully obtained auth code from Kong.")
            return {"redirect_uri": redirect_uri_from_kong}

    except httpx.RequestError as e:
        logger.error(f"HTTP request error: {e}")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail=f"An internal server error occurred: {type(e).__name__} - {e}")
