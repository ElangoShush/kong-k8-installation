
import requests

# The URL for your Kong Admin API, provided by the environment
KONG_ADMIN_URL = os.environ.get("KONG_ADMIN_URL") # 

# A simple in-memory cache for secrets
secret_cache = {}

def get_secret_for_consumer(username):
    """
    Fetches a consumer's JWT secret from the Kong Admin API, with caching.
    """
    if username in secret_cache:
        return secret_cache[username]

    if not KONG_ADMIN_URL:
        print("ERROR: KONG_ADMIN_URL is not set")
        return None

    try:
        response = requests.get(f"{KONG_ADMIN_URL}/consumers/{username}/jwt")
        response.raise_for_status() # Raise an exception for bad status codes
        data = response.json().get("data", [])
        if data:
            # Note: A consumer can have multiple JWT credentials, here we just take the first
            secret = data[0].get("secret")
            secret_cache[username] = secret # Cache the secret
            return secret
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch secret for '{username}': {e}")
        return None
    return None


@app.route("/")
def issue_jwt():
    consumer_username = request.headers.get("X-Consumer-Username")
    login_hint = request.headers.get("X-Login-Hint")

    if not consumer_username or not login_hint:
        return jsonify({"error": "Missing required headers"}), 400

    # Dynamically fetch the secret for the authenticated consumer
    jwt_secret = get_secret_for_consumer(consumer_username)

    if not jwt_secret:
        return jsonify({"error": f"Could not find secret for consumer '{consumer_username}'"}), 500

    # (I also corrected a typo here, the algorithm should be HS256)
    payload = { "iss": consumer_username, "login_hint": login_hint, ... }
    signed_jwt = jwt.encode(payload, jwt_secret, algorithm="HS256")
    
    return jsonify({"jwt": signed_jwt})