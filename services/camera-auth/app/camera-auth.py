import httpx
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qs
import logging
import os

# --- Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Pydantic Models for Request Validation ---
class AuthRequest(BaseModel):
    """Defines the expected structure of the incoming request body."""
    login_hint: str

# --- FastAPI Application Instance ---
app = FastAPI(
    title="Camera Authorizer Service",
    description="Orchestrates external authentication and the Kong OAuth2 flow.",
    version="1.0.0"
)

# --- Helper Function ---
def parse_code_from_uri(uri: str) -> str | None:
    """Extracts the 'code' query parameter from a URI."""
    try:
        parsed_url = urlparse(uri)
        query_params = parse_qs(parsed_url.query)
        # The value is a list, get the first element
        return query_params.get("code", [None])[0]
    except Exception as e:
        logger.error(f"Failed to parse code from URI: {uri}. Error: {e}")
        return None

# --- API Endpoint ---
@app.post("/oauth2/authorize")
async def handle_authorization(auth_request: AuthRequest, response: Response):
    """
    Main endpoint that Kong routes to. It orchestrates the full auth flow.
    """
    login_hint = auth_request.login_hint
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

            # --- Step 2: Check the response. If it fails, stop. ---
            if external_response.status_code != 200:
                logger.warning(f"External auth failed with status: {external_response.status_code}")
                raise HTTPException(status_code=401, detail="External user authentication failed")

            logger.info("External authentication successful.")

            # --- Step 3: Call Kong's internal /oauth2/authorize endpoint ---
            # Use the internal Kubernetes service name for Kong.
            kong_proxy_url = "https://kong-kong-proxy.kong.svc.cluster.local:8443/oauth2/authorize"
            kong_payload = {
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "https://oauth.pstmn.io/v1/callback",
                "scope": "sherlockapiresource/write",
                "provision_key": "OAuth-Token-Dispenser-Key",
                "authenticated_userid": "elango",
                "login_hint": login_hint
            }

            logger.info(f"Calling Kong's internal authorize endpoint: {kong_proxy_url}")
            # Use verify=False for self-signed certs typical in internal cluster communication
            kong_auth_response = await client.post(kong_proxy_url, data=kong_payload, verify=False)
            kong_auth_response.raise_for_status() # Raise an exception for non-2xx responses

            # --- Step 4: Extract the auth code from Kong's response ---
            response_data = kong_auth_response.json()
            redirect_uri = response_data.get("redirect_uri")
            if not redirect_uri:
                raise HTTPException(status_code=500, detail="Kong response missing redirect_uri")

            auth_code = parse_code_from_uri(redirect_uri)
            if not auth_code:
                raise HTTPException(status_code=500, detail="Could not parse auth code from redirect_uri")

            # --- Step 5: Send the auth code back to the client in a header ---
            logger.info(f"Successfully obtained auth code, returning it in X-Auth-Code header.")
            response.headers["X-Auth-Code"] = auth_code
            return {"status": "success", "message": "Authorization code generated."}

    except httpx.RequestError as e:
        logger.error(f"HTTP request error: {e}")
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred")
