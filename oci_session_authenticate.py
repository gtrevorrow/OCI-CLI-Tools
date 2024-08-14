import base64
import argparse
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key(key_size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())


def token_exchange_jwt_to_upst(token_exchange_url, client_cred, oci_public_key, subject_token):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {client_cred}'
    }
    data = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'requested_token_type': 'urn:oci:token-type:oci-upst',
        'public_key': oci_public_key,
        'subject_token': subject_token,
        'subject_token_type': 'jwt'
    }
    response = requests.post(token_exchange_url, headers=headers, data=data)
    return response.json()


def authenticate_via_oauth():
    # Configuration
    authZ_server_base_url = args.authZ_server_base_url
    device_auth_url = f"{authZ_server_base_url}/oauth2/v1/device"
    client_id = args.client_id
    client_secret = args.client_secret
    scope = args.scope

    #  1: Get the device code and user verification URL
    response = requests.post(device_auth_url,
                             data={"client_id": client_id, "scope": scope, "response_type": "device_code"})
    response_data = response.json()
    print(response_data)

    device_code = response_data["device_code"]
    user_code = response_data["user_code"]
    verification_url = response_data["verification_uri"]

    #  2: Print the user verification URL
    print(f"Please visit this URL and enter the code to authorize the application: {verification_url}")
    print(f"User code: {user_code}")

    #  3: Wait for the user to enter the user code
    input("Press Enter after you have authorized the application...")

    #  4: Exchange the device code for an access token
    token_url = f"{authZ_server_base_url}/oauth2/v1/token"  # replace with your OAuth server's token endpoint
    response = requests.post(token_url,
                             data={"client_id": client_id, "client_secret": client_secret, "device_code": device_code,
                                   "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
    print(response)
    access_token = response.json()["access_token"]
    print(f"Access token: {access_token}")

    #  5: Exchange the AT for a UPST
    client_creds = f"{client_id}:{client_secret}"
    auth_string_encoded = base64.b64encode(client_creds.encode()).decode()

    key = generate_key()

    public_key_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Base64 encode the public key
    public_key_b64 = base64.b64encode(public_key_bytes).decode()

    token_exchange_response = token_exchange_jwt_to_upst(token_url, auth_string_encoded, public_key_b64, access_token)
    print(token_exchange_response)
    print(f"UPST: {token_exchange_response['token']}")
    upst = token_exchange_response['token']
    # Write UPST to a file
    with open('token', 'w') as f:
        f.write(upst)

    # Write private key to a file
    with open('private_key.pem', 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OCI Session Authentication with OAuth Device Code grant')
    parser.add_argument('--authZ_server_base_url', required=True, help='Authorization server base URL')
    parser.add_argument('--client_id', required=True, help='Client ID')
    parser.add_argument('--client_secret', required=True, help='Client Secret')
    parser.add_argument('--scope', required=True, help='Scope')
    args = parser.parse_args()
    authenticate_via_oauth()
