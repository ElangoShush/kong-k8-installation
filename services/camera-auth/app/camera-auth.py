import httpx
from fastapi import FastAPI, HTTPException, Response, Form
import logging
from urllib.parse import urlparse, parse_qs

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
@app.post("/")  # <-- CORRECTED: Listens on the root path to avoid routing loops
async def handle_authorization(
    response: Response,
    # Use Form() to extract data from 'application/x-www-form-urlencoded'
    login_hint: str = Form(...),
    # These fields are captured from the client's request but passed on to Kong
    response_type: str = Form("code"),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(None),
    provision_key: str = Form(...),
    authenticated_userid: str = Form(...)
):
    logger.info(f"Received authorization request for login_hint: {login_hint}")

    # --- Step 1: Call External Authentication API ---
    external_api_url = "http://34.54.169.57/v0/authenticate_user"
    params = {
        "identifier": "ABC12345",
        "carrierName": "lab",
        "customerName": "Bank1",
        "msisdn": login_hint,
        "ipAddress": "192.168.0.1"
    }

    try:
        async with httpx.AsyncClient() as client:
            logger.info(f"Calling external auth API: {external_api_url}")
            external_response = await client.get(external_api_url, params=params)

            if external_response.status_code != 200:
                logger.warning(f"External auth failed with status: {external_response.status_code}")
                raise HTTPException(status_code=401, detail="External user authentication failed")

            logger.info("External authentication successful.")

            # --- Step 2: Call Kong's internal /oauth2/authorize endpoint ---
            kong_proxy_url = "https://kong-kong-proxy.kong.svc.cluster.local:8443/oauth2/authorize"
            
            # Construct the payload using the data passed from the original client
            kong_payload = {
                "response_type": response_type,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "provision_key": provision_key,
                "authenticated_userid": authenticated_userid,
                "login_hint": login_hint
            }
            # Filter out any None values
            kong_payload = {k: v for k, v in kong_payload.items() if v is not None}


            logger.info(f"Calling Kong's internal authorize endpoint with payload: {kong_payload}")
            kong_auth_response = await client.post(kong_proxy_url, data=kong_payload, verify=False)
            kong_auth_response.raise_for_status()

            response_data = kong_auth_response.json()
            redirect_uri_from_kong = response_data.get("redirect_uri")
            if not redirect_uri_from_kong:
                raise HTTPException(status_code=500, detail="Kong response missing redirect_uri")

            auth_code = parse_code_from_uri(redirect_uri_from_kong)
            if not auth_code:
                raise HTTPException(status_code=500, detail="Could not parse auth code from redirect_uri")

            logger.info(f"Successfully obtained auth code, returning it in X-Auth-Code header.")
            
            # --- Step 3: Return the original redirect URI from Kong ---
            # This is the standard OAuth2 behavior. The client will be redirected.
            return {"redirect_uri": redirect_uri_from_kong}

    except httpx.RequestError as e:
        logger.error(f"HTTP request error: {e}")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred")

