# app/main.py
import os, json, importlib.util, inspect
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse

SCRIPT_PATH = os.environ.get("SCRIPT_PATH", "/app/ts43-issue-auth-code.py")

def _load_script(path: str):
    spec = importlib.util.spec_from_file_location("ts43_issue_auth_code", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod

mod = _load_script(SCRIPT_PATH)

# Try common handler names in the uploaded script
POSSIBLE = ["lambda_handler", "handler", "issue_auth_code"]
HANDLER = None
for name in POSSIBLE:
    fn = getattr(mod, name, None)
    if callable(fn):
        HANDLER = fn
        break

app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/v2/issue_auth_code")
async def issue_auth_code(
    request: Request,
    client_id: str = Header(...),
    client_secret: str = Header(...)
):
    body_text = await request.body()
    try:
        body_json = json.loads(body_text.decode() or "{}")
    except Exception:
        body_json = {}

    # Prefer Lambda-style: handler(event, context) -> {"statusCode", "body", "headers"}
    if HANDLER:
        event = {
            "headers": {"client_id": client_id, "client_secret": client_secret},
            "body": json.dumps(body_json),
            "rawBody": body_json,
        }
        try:
            result = HANDLER(event, None) if len(inspect.signature(HANDLER).parameters) >= 1 else HANDLER()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"handler error: {e}")

        # Normalize Lambda-style response
        if isinstance(result, dict) and "statusCode" in result:
            status = int(result.get("statusCode", 200))
            headers = result.get("headers") or {}
            body = result.get("body")
            try:
                body = json.loads(body) if isinstance(body, str) else body
            except Exception:
                pass
            return JSONResponse(status_code=status, content=body, headers=headers)

        # If script returned a plain dict, pass it through
        if isinstance(result, dict):
            return JSONResponse(status_code=200, content=result)

        return JSONResponse(status_code=200, content={"result": str(result)})

    # Fallback if no handler found
    raise HTTPException(
        status_code=500,
        detail=f"No callable handler found in {SCRIPT_PATH}. Expected one of: {POSSIBLE}"
    )
