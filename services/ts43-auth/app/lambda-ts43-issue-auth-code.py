import os
import json
import uuid
import redis
import base64
import requests
from requests.auth import HTTPBasicAuth

def error_response(status_code, message):
    return {
        "statusCode": status_code,
        "body": json.dumps({"error": message}),
        "headers": {
            "Content-Type": "application/json"
        }
    }

def lambda_handler(event, context):
    headers = event.get("headers", {})
    client_id = headers.get("client_id")
    client_secret = headers.get("client_secret")

    if not client_id:
        return error_response(400, "BAD REQUEST: Missing 'client_id' in headers")
    if not client_secret:
        return error_response(400, "BAD REQUEST: Missing 'client_secret' in headers")


    # Validate with Cognito
    token_url = f"https://{os.environ['COGNITO_DOMAIN']}/oauth2/token"
    try:
        response = requests.post(
            token_url,
            data={"grant_type": "client_credentials", "scope": "sherlockapiresource/write"},
            auth=HTTPBasicAuth(client_id, client_secret),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if response.status_code != 200:
            return error_response(401, "UNAUTHENTICATED: Request not authenticated due to missing, invalid, or expired credentials")
    except Exception as e:
        return error_response(500, f"INTERNAL: Cognito validation failed: {str(e)}")

    # Prepare and encode credentials as Base64
    combined = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(combined.encode('utf-8')).decode('utf-8')

    # Generate and store auth_code in Redis
    auth_code = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip("=")
    redis_key = f"auth_code:{auth_code}"
    try:
        redis_client = redis.Redis(
            host=os.environ["REDIS_HOST"],
            port=int(os.environ["REDIS_PORT"]),
            ssl=True,
            decode_responses=True
        )
        redis_client.setex(redis_key, 120, encoded_credentials)
    except Exception as e:
        return error_response(500, f"INTERNAL: Redis error: {str(e)}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "auth_code": auth_code,
            "expires_in": 120
        }),
        "headers": {
            "Content-Type": "application/json"
        }
    }
