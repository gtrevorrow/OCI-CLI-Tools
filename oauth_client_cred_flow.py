import requests

def get_access_token(client_id, client_secret, token_url):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
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
    client_id = 'your_client_id'
    client_secret = 'your_client_secret'
    token_url = 'https://example.com/oauth2/token'
    api_url = 'https://example.com/api/resource'

    access_token = get_access_token(client_id, client_secret, token_url)
    response_data = make_authenticated_request(access_token, api_url)
    print(response_data)