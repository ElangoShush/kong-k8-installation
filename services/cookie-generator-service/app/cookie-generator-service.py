import os
import sys
import base64
import time
import httpx
import json
from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.responses import JSONResponse, PlainTextResponse

# --- Environment Variables ---
# For proxying requests
BACKEND_API_URL = os.getenv("BACKEND_API_URL")
# For fetching client_secret and getting a token same as cookie auth
KONG_ADMIN_URL = os.getenv("KONG_ADMIN_URL")
KONG_INTERNAL_OAUTH_URL = os.getenv("KONG_INTERNAL_OAUTH_URL")

# Validate that required environment variables are set during deployment
missing_vars = []
if not BACKEND_API_URL: missing_vars.append("BACKEND_API_URL")
if not KONG_ADMIN_URL: missing_vars.append("KONG_ADMIN_URL")
if not KONG_INTERNAL_OAUTH_URL: missing_vars.append("KONG_INTERNAL_OAUTH_URL")

if missing_vars:
    sys.stderr.write(f"Error: Required environment variables are not set: {', '.join(missing_vars)}\n")
    sys.exit(1)

if not BACKEND_API_URL:
    sys.stderr.write("Error: Required environment variable BACKEND_API_URL is not set.\n")
    sys.exit(1)

app = FastAPI(
    title="TS43 Auth & Token Service",
    description="ts 43 auth to issue cookie, authcode and JWT tokwn",
    version="1.4.0" 
)

# --- Helper Functions ---

def generate_session_cookie(eapid: str) -> str:
    if not isinstance(eapid, str) or not eapid:
        return ""
    try:
        random_bytes = os.urandom(32)
        encoded_random_part = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        combined_string = f"{encoded_random_part},eapid:{eapid}"
        final_value = base64.b64encode(combined_string.encode('utf-8')).decode('utf-8')
        return final_value
    except Exception as e:
        print(f"Error generating session cookie: {e}")
        return ""

def generate_intermediate_code(seed_value: str) -> str:
    try:
        timestamp = str(int(time.time())).encode('utf-8')
        random_bytes = os.urandom(16)
        seed_bytes = seed_value.encode('utf-8')
        combined_raw = timestamp + b":" + random_bytes + b":" + seed_bytes
        intermediate_code = base64.urlsafe_b64encode(combined_raw).decode('utf-8').rstrip('=')
        return intermediate_code
    except Exception as e:
        print(f"Error generating intermediate code: {e}")
        return ""

def extract_eapid_from_setcookie(setcookie_header: str) -> str | None:
    if not setcookie_header:
        print("Error: 'setcookie' header is missing from incoming request.")
        return None
    try:
        # Add padding if necessary for correct Base64 decoding
        padding = '=' * (4 - len(setcookie_header) % 4)
        decoded_bytes = base64.b64decode(setcookie_header + padding)
        decoded_string = decoded_bytes.decode('utf-8')

        # Split the string to find the eapid part
        parts = decoded_string.split(',eapid:')
        if len(parts) == 2:
            eapid = parts[1]
            print(f"Successfully extracted eapid '{eapid}' from setcookie header.")
            return eapid
        else:
            print(f"Error: Decoded 'setcookie' string is not in the expected format: {decoded_string}")
            return None
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        print(f"Error decoding 'setcookie' header: {e}")
        return None

async def get_client_secret_from_kong(client_id: str) -> str | None:
    oauth2_url = f"{KONG_ADMIN_URL.rstrip('/')}/oauth2"
    params = {"client_id": client_id}
    try:
        async with httpx.AsyncClient() as client:
            print(f"Querying Kong Admin API: {oauth2_url} for client_id: {client_id}")
            response = await client.get(oauth2_url, params=params, timeout=5.0)
        
        response.raise_for_status()
        oauth_data = response.json()

        if oauth_data.get("data") and len(oauth_data["data"]) > 0:
            client_secret = oauth_data["data"][0].get("client_secret")
            if client_secret:
                print(f"Successfully retrieved client_secret for client_id: {client_id}")
                return client_secret
        
        print(f"Warning: No OAuth2 credential or secret found for client_id: {client_id}")
        return None
    except httpx.RequestError as e:
        print(f"Error calling Kong Admin API: {e}"); return None
    except httpx.HTTPStatusError as e:
        print(f"Error response from Kong Admin API: {e.response.status_code} {e.response.text}"); return None


# --- API Endpoints ---

@app.get("/healthz")
def healthz():
    """Health check endpoint."""
    return {"status": "ok"}

@app.get("/v2/authenticate_ts43_client")
async def proxy_and_set_cookie(request: Request):
    eapid_header = request.headers.get("eapid")
    if not eapid_header:
        return PlainTextResponse("Bad Request: Missing 'eapid' header.", status_code=400)

    async with httpx.AsyncClient() as client:
        try:
            url = f"{BACKEND_API_URL}{request.url.path}?{request.query_params}"
            backend_response = await client.get(url, headers=dict(request.headers), timeout=10.0)
        except httpx.RequestError as e:
            return PlainTextResponse(f"Bad Gateway: Upstream service is unavailable. Error: {e}", status_code=502)
    client_response = Response(content=backend_response.content, status_code=backend_response.status_code, headers=dict(backend_response.headers))
    if backend_response.status_code == 200:
        cookie_value = generate_session_cookie(eapid_header)
        if cookie_value:
            client_response.set_cookie(key="session_id", value=cookie_value, path="/", samesite="lax")
            print(f"Successfully set session cookie for eapid: {eapid_header}")
    return client_response

@app.post("/v2/authenticate_ts43_client")
async def proxy_and_generate_authcode(request: Request):
    # 1. Get eapid from the 'setcookie' header of the incoming request
    setcookie_header_from_request = request.headers.get("setcookie")
    extracted_eapid = extract_eapid_from_setcookie(setcookie_header_from_request)

    if not extracted_eapid:
        return PlainTextResponse("Bad Request: Invalid or missing 'setcookie' header in request.", status_code=400)

    async with httpx.AsyncClient() as client:
        try:
            url = f"{BACKEND_API_URL}{request.url.path}"
            backend_response = await client.post(
                url, headers=dict(request.headers), params=dict(request.query_params),
                content=await request.body(), timeout=10.0
            )
        except httpx.RequestError as e:
            return PlainTextResponse(f"Bad Gateway: Upstream service unavailable. Error: {e}", status_code=502)

    if backend_response.status_code != 200:
        return Response(content=backend_response.content, status_code=backend_response.status_code, headers=dict(backend_response.headers))

    try:
        backend_body_json = backend_response.json()
        cookie_value_from_backend = backend_body_json.get("setCookie")

        if not cookie_value_from_backend:
            print("Warning: Backend JSON response is 200 OK but is missing the 'setCookie' key.")
            return JSONResponse(content=backend_body_json, status_code=200)

        # 2. Generate the intermediate code using the backend's response value.
        intermediate_code = generate_intermediate_code(cookie_value_from_backend)
        if not intermediate_code:
            return JSONResponse(content={"error": "Failed to generate intermediate code"}, status_code=500)

        # 3. Construct the final string using the eapid extracted from the request header.
        final_string_to_encode = f"({intermediate_code},eapid:{extracted_eapid})"

        # 4. Base64 encode the final string to create the final auth_code.
        final_auth_code = base64.b64encode(final_string_to_encode.encode('utf-8')).decode('utf-8')

        # Add the final auth_code to the response JSON.
        backend_body_json["auth_code"] = final_auth_code
        print(f"Successfully generated and injected final auth_code for eapid: {extracted_eapid}")

        return JSONResponse(content=backend_body_json, status_code=200)

    except json.JSONDecodeError:
        return PlainTextResponse("Bad Gateway: Upstream service returned a non-JSON response.", status_code=502)

@app.get("/v2/ts43_operator_token")
async def get_operator_token(client_id: str = Header(..., alias="client_id")):
    print(f"Received token request for client_id: {client_id}")
    
    # 1. Get the client_secret from Kong Admin API
    client_secret = await get_client_secret_from_kong(client_id)
    if not client_secret:
        raise HTTPException(status_code=401, detail="Invalid client_id or client credentials not found.")

    # 2. Call Kong's internal /oauth2/token endpoint
    kong_token_url = f"{KONG_INTERNAL_OAUTH_URL.rstrip('/')}/oauth2/token"
    kong_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            print(f"Requesting access token from Kong at {kong_token_url}")
            kong_resp = await client.post(kong_token_url, data=kong_payload, timeout=10.0)
        
        # Pass through Kong's response (both success and failure) to the client
        return Response(
            content=kong_resp.content,
            status_code=kong_resp.status_code,
            headers={"Content-Type": "application/json"}
        )
            
    except httpx.RequestError as e:
        print(f"Error calling Kong token endpoint: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable: Could not connect to the authentication server.")

