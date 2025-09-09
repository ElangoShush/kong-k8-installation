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
    version="1.1.0"
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

def generate_auth_code(seed_value: str) -> str:
    try:
        timestamp = str(int(time.time())).encode('utf-8')
        random_bytes = os.urandom(16)
        seed_bytes = seed_value.encode('utf-8')

        # Combine all parts for a strong, unique value
        combined_raw = timestamp + b":" + random_bytes + b":" + seed_bytes

        # Use URL-safe Base64 encoding for the final code
        auth_code = base64.urlsafe_b64encode(combined_raw).decode('utf-8').rstrip('=')
        return auth_code
    except Exception as e:
        print(f"Error generating auth code: {e}")
        return ""

def parse_cookie_from_header(header_value: str) -> str | None:
    if not header_value:
        return None
    try:
        # The value is the part before the first semicolon
        first_part = header_value.split(';')[0]
        # The value is the part after the first equals sign
        value = first_part.split('=', 1)[1]
        return value.strip()
    except IndexError:
        print(f"Could not parse cookie from header: {header_value}")
        return None


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
    # 1. Proxy the request to the backend API
    async with httpx.AsyncClient() as client:
        try:
            # Construct the full URL for the backend service
            url = f"{BACKEND_API_URL}{request.url.path}"

            # Forward the request exactly as it was received
            backend_response = await client.post(
                url,
                headers=dict(request.headers),
                params=dict(request.query_params),
                content=await request.body(),
                timeout=10.0
            )
        except httpx.RequestError as e:
            return PlainTextResponse(f"Bad Gateway: Upstream service unavailable. Error: {e}", status_code=502)

    # 2. Process the backend response
    if backend_response.status_code != 200:
        # If the backend call failed, pass its response through unmodified
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers)
        )

    # 3. On success, generate auth_code and modify the response body
    try:
        backend_body_json = backend_response.json()
        set_cookie_header = backend_response.headers.get("set-cookie")

        if not set_cookie_header:
            print("Warning: Backend response is 200 OK but is missing the 'set-cookie' header.")
            # Return the original body without an auth_code
            return JSONResponse(content=backend_body_json, status_code=200)

        # Extract the cookie value to use as a seed for our auth code
        cookie_value = parse_cookie_from_header(set_cookie_header)

        if not cookie_value:
             print("Warning: Could not parse cookie value from header. Returning original response.")
             return JSONResponse(content=backend_body_json, status_code=200)

        # Generate the new auth code
        auth_code = generate_auth_code(cookie_value)

        if not auth_code:
            # Handle failure in code generation
            return JSONResponse(content={"error": "Failed to generate auth code"}, status_code=500)

        # Add the auth_code to the response JSON
        backend_body_json["auth_code"] = auth_code
        print(f"Successfully generated and injected auth_code.")

        # Return the modified JSON response to the original client
        return JSONResponse(content=backend_body_json, status_code=200)

    except json.JSONDecodeError:
        return PlainTextResponse("Bad Gateway: Upstream service returned a non-JSON response.", status_code=502)

