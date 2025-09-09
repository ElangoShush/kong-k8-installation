import os
import sys
import base64
import time
import httpx
import json
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

# --- Environment Variables ---
BACKEND_API_URL = os.getenv("BACKEND_API_URL")

if not BACKEND_API_URL:
    sys.stderr.write("Error: Required environment variable BACKEND_API_URL is not set.\n")
    sys.exit(1)

app = FastAPI(
    title="Camera Auth Service",
    description="A proxy service that injects an auth_code or sets a cookie.",
    version="1.2.0" 
)

# --- Helper Functions ---

def generate_session_cookie(eapid: str) -> str:
    """
    (Unchanged) Generates a cookie value for the GET method.
    """
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

def generate_auth_code(seed_value: str) -> str:
    """
    (Unchanged) Generates a secure, random authorization code.
    """
    try:
        timestamp = str(int(time.time())).encode('utf-8')
        random_bytes = os.urandom(16)
        seed_bytes = seed_value.encode('utf-8')
        combined_raw = timestamp + b":" + random_bytes + b":" + seed_bytes
        auth_code = base64.urlsafe_b64encode(combined_raw).decode('utf-8').rstrip('=')
        return auth_code
    except Exception as e:
        print(f"Error generating auth code: {e}")
        return ""

# --- API Endpoints ---

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/v2/authenticate_ts43_client")
async def proxy_and_set_cookie(request: Request):
    eapid_header = request.headers.get("eapid")
    if not eapid_header:
        return PlainTextResponse("Bad Request: Missing 'eapid' header.", status_code=400)

    async with httpx.AsyncClient() as client:
        try:
            url = f"{BACKEND_API_URL}{request.url.path}?{request.query_params}"
            backend_response = await client.get(
                url,
                headers=dict(request.headers),
                timeout=10.0
            )
        except httpx.RequestError as e:
            return PlainTextResponse(f"Bad Gateway: Upstream service is unavailable. Error: {e}", status_code=502)

    client_response = Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=dict(backend_response.headers)
    )

    if backend_response.status_code == 200:
        cookie_value = generate_session_cookie(eapid_header)
        if cookie_value:
            client_response.set_cookie(key="session_id", value=cookie_value, path="/", samesite="lax")
            print(f"Successfully set session cookie for eapid: {eapid_header}")

    return client_response

@app.post("/v2/authenticate_ts43_client")
async def proxy_and_generate_authcode(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            url = f"{BACKEND_API_URL}{request.url.path}"
            backend_response = await client.post(
                url,
                headers=dict(request.headers),
                params=dict(request.query_params),
                content=await request.body(),
                timeout=10.0
            )
        except httpx.RequestError as e:
            return PlainTextResponse(f"Bad Gateway: Upstream service unavailable. Error: {e}", status_code=502)

    if backend_response.status_code != 200:
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers)
        )

    try:
        backend_body_json = backend_response.json()
        
        cookie_value = backend_body_json.get("setCookie")

        if not cookie_value:
            print("Warning: Backend JSON response is 200 OK but is missing the 'setCookie' key.")
            return JSONResponse(content=backend_body_json, status_code=200)

        auth_code = generate_auth_code(cookie_value)

        if not auth_code:
            return JSONResponse(content={"error": "Failed to generate auth code"}, status_code=500)

        # Add the auth_code to the response JSON
        backend_body_json["auth_code"] = auth_code
        print(f"Successfully generated and injected auth_code.")

        return JSONResponse(content=backend_body_json, status_code=200)

    except json.JSONDecodeError:
        return PlainTextResponse("Bad Gateway: Upstream service returned a non-JSON response.", status_code=502)

