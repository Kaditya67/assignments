import os
import json
import secrets
import base64
import time
import requests
import logging
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem

logger = logging.getLogger("hubspot_oauth")
logging.basicConfig(level=logging.INFO)

CLIENT_ID = os.environ.get("HUBSPOT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("HUBSPOT_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
SCOPES = "crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read"

authorization_url = (
    f"https://app.hubspot.com/oauth/authorize"
    f"?client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&scope={SCOPES.replace(' ', '%20')}"
)

async def authorize_hubspot(user_id, org_id):
    logger.info(f"Starting OAuth authorization for user {user_id} in org {org_id}")
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
    await add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=600)
    url = f"{authorization_url}&state={encoded_state}"
    logger.info(f"Authorization URL generated: {url}")
    return url

async def oauth2callback_hubspot(request: Request):
    logger.info(f"Received OAuth callback request: {request.query_params}")
    if request.query_params.get("error"):
        error_desc = request.query_params.get("error_description")
        logger.error(f"OAuth error: {error_desc}")
        raise HTTPException(status_code=400, detail=error_desc)
    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")

    try:
        state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode())
    except Exception as e:
        logger.error(f"Error decoding state data: {e}")
        raise HTTPException(status_code=400, detail="Invalid state parameter.")

    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")
    state = state_data.get("state")

    saved_state_raw = await get_value_redis(f"hubspot_state:{org_id}:{user_id}")
    if not saved_state_raw:
        logger.error("Saved state not found in Redis.")
        raise HTTPException(status_code=400, detail="State timeout or missing.")
    saved_state = json.loads(saved_state_raw)
    if state != saved_state.get("state"):
        logger.error("State mismatch detected. Potential CSRF attack.")
        raise HTTPException(status_code=400, detail="State does not match.")

    token_url = "https://api.hubapi.com/oauth/v1/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    resp = requests.post(token_url, data=payload, headers=headers)
    logger.info(f"Token exchange status: {resp.status_code}")
    if resp.status_code != 200:
        logger.error(f"Token exchange failed: {resp.text}")
        raise HTTPException(status_code=resp.status_code, detail="Failed to exchange token.")

    tokens = resp.json()
    if "expires_in" in tokens:
        tokens["expires_at"] = int(time.time()) + int(tokens["expires_in"]) - 60

    await add_key_value_redis(f"hubspot_credentials:{org_id}:{user_id}", json.dumps(tokens))
    await delete_key_redis(f"hubspot_state:{org_id}:{user_id}")

    logger.info(f"Tokens saved for user {user_id} in org {org_id}.")

    return HTMLResponse("<html><script>window.close();</script></html>")

async def get_hubspot_credentials(user_id, org_id):
    logger.info(f"Retrieving HubSpot credentials for user {user_id}, org {org_id}")
    cred_key = f"hubspot_credentials:{org_id}:{user_id}"
    credentials_raw = await get_value_redis(cred_key)
    if not credentials_raw:
        logger.error("No credentials found in Redis.")
        raise HTTPException(status_code=400, detail="No HubSpot credentials found.")

    credentials = json.loads(credentials_raw)
    current_time = int(time.time())

    if credentials.get("expires_at", 0) < current_time:
        logger.info("Access token expired; refreshing...")
        payload = {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": credentials["refresh_token"],
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = requests.post("https://api.hubapi.com/oauth/v1/token", data=payload, headers=headers)
        if resp.status_code != 200:
            logger.error(f"Token refresh failed: {resp.text}")
            raise HTTPException(status_code=resp.status_code, detail="Failed to refresh token.")

        new_tokens = resp.json()
        credentials.update(new_tokens)
        if "expires_in" in new_tokens:
            credentials["expires_at"] = current_time + int(new_tokens["expires_in"]) - 60
        await add_key_value_redis(cred_key, json.dumps(credentials))
        logger.info("Token refresh successful and saved.")

    return credentials

def create_integration_item_metadata_object(obj, item_type):
    if item_type == "Contact":
        name = f"{obj.get('properties', {}).get('firstname', '')} {obj.get('properties', {}).get('lastname', '')}".strip()
    else:
        name = obj.get('properties', {}).get('name', '')
    item = IntegrationItem(
        id=obj.get("id"),
        type=item_type,
        name=name,
        parent_id=None,
        parent_path_or_name=None,
    )
    logger.info(f"Created IntegrationItem: {item.__dict__}")
    return item

async def get_items_hubspot(credentials):
    logger.info("Fetching HubSpot data...")
    if isinstance(credentials, str):
        credentials = json.loads(credentials)

    access_token = credentials.get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}
    items = []
    endpoints = [
        ("Contact", "https://api.hubapi.com/crm/v3/objects/contacts"),
        ("Company", "https://api.hubapi.com/crm/v3/objects/companies"),
        ("Deal", "https://api.hubapi.com/crm/v3/objects/deals"),
    ]

    for item_type, url in endpoints:
        resp = requests.get(url, headers=headers)
        logger.info(f"Fetching {item_type}s: Status {resp.status_code}")
        if resp.status_code == 200:
            for obj in resp.json().get("results", []):
                items.append(create_integration_item_metadata_object(obj, item_type))
        else:
            logger.error(f"Failed to fetch {item_type}s: {resp.text}")

    logger.info(f"Total items fetched: {len(items)}")
    return items
