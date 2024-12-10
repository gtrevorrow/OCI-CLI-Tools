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
    response_data = response.json()
    return response_data['access_token']


def make_authenticated_request(access_token, api_url):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(api_url, headers=headers)
    return response.json()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Client Credential Grant Flow')
    parser.add_argument('--configFile', required=True, help='Config File')
    parser.add_argument('--token', required=True, help='Domain Access Token')
    args = parser.parse_args()
    # Read the configuration file to get the client_id, client_secret, token_url
    config = toml.load(args.configFile)
    client_id = config['client_id']
    client_secret = config['client_secret']
    token_url = config['token_url']
    access_token = get_access_token(client_id, client_secret, token_url)
    #Save access token to --token file
    with open(args.token, 'w') as token_file:
        token_file.write(access_token)
    print(f'Access token: {access_token}')
