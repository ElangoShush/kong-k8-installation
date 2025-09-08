# app.py
import os
import sys
import base64
import httpx  # An async-compatible requests library
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse

BACKEND_API_URL = os.getenv("BACKEND_API_URL")

if not BACKEND_API_URL:
    sys.stderr.write("Error: Required environment variable BACKEND_API_URL is not set.\n")
    sys.exit(1)

app = FastAPI(
    title="Cookie Generator Microservice",
    description="A proxy service that adds a session cookie on successful authentication.",
    version="1.0.0"
)

def generate_session_cookie(eapid: str) -> str:
    if not isinstance(eapid, str) or not eapid:
        return ""

    try:
        random_bytes = os.urandom(32)
        eapid_bytes = eapid.encode('utf-8')
        separator_bytes = b':'
        combined_bytes = random_bytes + separator_bytes + eapid_bytes
        encoded_cookie_value = base64.b64encode(combined_bytes).decode('utf-8')
        return encoded_cookie_value
    except Exception as e:
        # In a real app, you would log this error.
        print(f"Error generating cookie: {e}")
        return ""

@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.api_route("/v2/authenticate_ts43_client", methods=["GET", "POST"])
async def proxy_and_set_cookie(request: Request):
    eapid_header = request.headers.get("eapid")
    if not eapid_header:
        return PlainTextResponse("Bad Request: Missing 'eapid' header.", status_code=400)

    async with httpx.AsyncClient() as client:
        try:
            body = await request.body()
            headers = dict(request.headers)

            backend_response = await client.request(
                method=request.method,
                url=f"{BACKEND_API_URL}{request.url.path}",
                headers=headers,
                content=body,
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
            client_response.set_cookie(
                key="session_id",
                value=cookie_value,
                httponly=True,
                secure=True,
                samesite='lax'
            )
            print(f"Successfully set session cookie for eapid: {eapid_header}")

    return client_response