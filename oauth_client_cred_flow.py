import argparse

import requests
import toml


def get_access_token(client_id, client_secret, token_url):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'urn:opc:idm:__myscopes__'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(token_url, data=payload, headers=headers)
    
    # Print response for debugging
    print(f"Response status code: {response.status_code}")
    print(f"Response body: {response.text}")
    
    if response.status_code != 200:
        raise Exception(f"Error getting token: {response.status_code}, {response.text}")
        
    response_data = response.json()
    
    # Print keys in response_data for debugging
    print(f"Response data keys: {list(response_data.keys())}")
    
    # Try different possible key names for the token
    for key in ['access_token', 'token', 'accessToken']:
        if key in response_data:
            return response_data[key]
    
    # If no known token key is found, raise an error with the response data
    raise KeyError(f"Could not find access token in response. Available keys: {list(response_data.keys())}")


def make_authenticated_request(access_token, api_url):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(api_url, headers=headers)
    return response.json()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Client Credential Grant Flow')
    parser.add_argument('--configFile', required=True, help='Config File')
    parser.add_argument('--token', required=False, help='Domain Access Token')
    args = parser.parse_args()
    # Read the configuration file to get the client_id, client_secret, token_url
    config = toml.load(args.configFile)
    client_id = config['client_id']
    client_secret = config['client_secret']
    token_url = config['token_url']
    access_token = get_access_token(client_id, client_secret, token_url)
    
    # Save access token to --token file if token argument was provided
    if args.token:
        with open(args.token, 'w') as token_file:
            token_file.write(access_token)
    
    print(f'Access token: {access_token}')
