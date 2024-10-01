import argparse
import requests
import json


def create_service_user(host, token, user_name):

    url = f"{host}/admin/v1/Users"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User"
        ],
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User": {
            "serviceUser": True
        },
        "userName": user_name,
        "name": {
            "givenName": "Service",
            "familyName": "User"
        },
        "emails": [
            {
                "value": "service.user@example.com",
                "type": "work",
                "primary": True
            }
        ]
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    print(response.status_code)
    try:
        print(response.json())
    except ValueError:
        print("Invalid JSON response")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create Service User')
    parser.add_argument('--host', required=True, help='Host URL')
    parser.add_argument('--token', required=True, help='Access Token')
    parser.add_argument('--user_name', required=True, help='Service User Name')

    args = parser.parse_args()
    with open(args.token, 'r') as token_file:
        token = token_file.read().strip()
    create_service_user(args.host, token, args.user_name)
