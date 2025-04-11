# hubspot.py

import json
import secrets
import hashlib
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import requests
from typing import List
from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

from dotenv import load_dotenv
import os

load_dotenv()
CLIENT_ID = os.getenv("HUBSPOT_CLIENT_ID")
CLIENT_SECRET = os.getenv("HUBSPOT_CLIENT_SECRET")

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}'

encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

scope = 'crm.objects.contacts.read crm.objects.contacts.write'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    
    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')
    
    auth_url = f'{authorization_url}&state={encoded_state}&code_challenge={code_challenge}&code_challenge_method=S256&scope={scope}'

    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )
    
    return auth_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')
    
    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )
    
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')
    
    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uri': REDIRECT_URI,
                    'code': code,
                    'code_verifier': code_verifier.decode('utf-8') if isinstance(code_verifier, bytes) else code_verifier,
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        )
    
    await add_key_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}', 
        json.dumps(response.json()), 
        expire=600
    )
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    
    return credentials

def create_integration_item_metadata_object(
    response_json: dict, item_type: str
) -> IntegrationItem:
    properties = response_json.get('properties', {})
    first_name = properties.get('firstname', '')
    last_name = properties.get('lastname', '')
    name = f"{first_name} {last_name}".strip()
    if not name:
        name = f"Contact {response_json.get('id')}"
    
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id'),
        name=name,
        type=item_type,
    )
    
    return integration_item_metadata

def fetch_items(
    access_token: str, url: str, aggregated_response: list, after=None
) -> None:
    """Fetching the list of contacts"""
    params = {'after': after} if after is not None else {}
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        
        for item in results:
            aggregated_response.append(item)
        
        paging = data.get('paging', {})
        if paging and 'next' in paging and paging.get('next', {}).get('after'):
            after = paging['next']['after']
            fetch_items(access_token, url, aggregated_response, after)
        
    else:
        print(f"Error fetching data: {response.status_code} - {response.text}")

async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    credentials = json.loads(credentials)
    url = 'https://api.hubapi.com/crm/v3/objects/contacts'
    list_of_integration_item_metadata = []
    list_of_responses = []

    fetch_items(credentials.get('access_token'), url, list_of_responses)
    for response in list_of_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'Contact')
        )
    
    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata