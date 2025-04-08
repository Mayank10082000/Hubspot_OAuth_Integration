# hubspot.py

import json
import secrets
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
# Define the scopes needed for the integration
scope = 'crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read'

async def authorize_hubspot(user_id, org_id):
    """
    Generate the authorization URL for HubSpot OAuth
    """
    # Create a unique state value to prevent CSRF attacks
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    
    # Store the state in Redis for later validation
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)
    
    # Construct the full authorization URL with state and scopes
    auth_url = f'{authorization_url}&state={encoded_state}&scope={scope}'
    
    return auth_url

async def oauth2callback_hubspot(request: Request):
    """
    Handle the OAuth callback from HubSpot
    """
    # Check for error response
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description', 'OAuth error'))
    
    # Get code and state from query parameters
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    
    # Decode state data
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))
    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')
    
    # Retrieve saved state from Redis
    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    
    # Validate the state to prevent CSRF attacks
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uri': REDIRECT_URI,
                    'code': code
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )
    
    # Store credentials in Redis
    await add_key_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}', 
        json.dumps(response.json()), 
        expire=600
    )
    
    # Return HTML to close the popup window
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    """
    Retrieve stored HubSpot credentials
    """
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    
    return credentials

def create_integration_item_metadata_object(
    item, item_type, parent_id=None, parent_name=None
) -> IntegrationItem:
    """
    Create an IntegrationItem object from HubSpot object data
    """
    item_id = item.get('id', '')
    properties = item.get('properties', {})
    
    # Define name based on item type
    if item_type == 'contact':
        name = f"{properties.get('firstname', '')} {properties.get('lastname', '')}"
    elif item_type == 'company':
        name = properties.get('name', '')
    elif item_type == 'deal':
        name = properties.get('dealname', '')
    else:
        name = f"HubSpot {item_type}"
    
    # Clean up empty name
    if not name or name.isspace():
        name = f"HubSpot {item_type} {item_id}"
    
    # Create the integration item
    integration_item = IntegrationItem(
        id=f"{item_id}_{item_type}",
        name=name,
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
        creation_time=properties.get('createdate'),
        last_modified_time=properties.get('lastmodifieddate'),
    )
    
    return integration_item

async def get_items_hubspot(credentials) -> List[IntegrationItem]:
    """
    Retrieve items from HubSpot and convert to IntegrationItem objects
    """
    # Parse credentials
    if isinstance(credentials, str):
        credentials = json.loads(credentials)
    
    access_token = credentials.get('access_token')
    
    # Common headers for API requests
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    
    list_of_items = []
    
    # Fetch companies
    try:
        company_response = requests.get(
            'https://api.hubapi.com/crm/v3/objects/companies',
            headers=headers,
            params={'limit': 100}
        )
        
        if company_response.status_code == 200:
            company_data = company_response.json()
            companies = company_data.get('results', [])
            
            # Add parent company item
            company_parent = IntegrationItem(
                id="hubspot_companies",
                name="HubSpot Companies",
                type="companies_folder",
                directory=True
            )
            list_of_items.append(company_parent)
            
            # Add individual companies
            for company in companies:
                company_item = create_integration_item_metadata_object(
                    company, 
                    'company',
                    "hubspot_companies",
                    "HubSpot Companies"
                )
                list_of_items.append(company_item)
    except Exception as e:
        print(f"Error fetching companies: {str(e)}")
    
    # Fetch contacts
    try:
        contact_response = requests.get(
            'https://api.hubapi.com/crm/v3/objects/contacts',
            headers=headers,
            params={'limit': 100}
        )
        
        if contact_response.status_code == 200:
            contact_data = contact_response.json()
            contacts = contact_data.get('results', [])
            
            # Add parent contact item
            contact_parent = IntegrationItem(
                id="hubspot_contacts",
                name="HubSpot Contacts",
                type="contacts_folder",
                directory=True
            )
            list_of_items.append(contact_parent)
            
            # Add individual contacts
            for contact in contacts:
                contact_item = create_integration_item_metadata_object(
                    contact, 
                    'contact',
                    "hubspot_contacts",
                    "HubSpot Contacts"
                )
                list_of_items.append(contact_item)
    except Exception as e:
        print(f"Error fetching contacts: {str(e)}")
    
    # Fetch deals
    try:
        deal_response = requests.get(
            'https://api.hubapi.com/crm/v3/objects/deals',
            headers=headers,
            params={'limit': 100}
        )
        
        if deal_response.status_code == 200:
            deal_data = deal_response.json()
            deals = deal_data.get('results', [])
            
            # Add parent deal item
            deal_parent = IntegrationItem(
                id="hubspot_deals",
                name="HubSpot Deals",
                type="deals_folder",
                directory=True
            )
            list_of_items.append(deal_parent)
            
            # Add individual deals
            for deal in deals:
                deal_item = create_integration_item_metadata_object(
                    deal, 
                    'deal',
                    "hubspot_deals",
                    "HubSpot Deals"
                )
                list_of_items.append(deal_item)
    except Exception as e:
        print(f"Error fetching deals: {str(e)}")
    
    # Print the items for debugging (as suggested in the assessment instructions)
    print(f"HubSpot items: {list_of_items}")
    
    return list_of_items