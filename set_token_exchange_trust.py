
import argparse
import requests

def set_token_exchange_trust(args):
    url = args.url
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.26.0",
        "Authorization": "Bearer " + args.token
    }
    payload = {
        "active": True,
        "allowImpersonation": False,
        "issuer": args.issuer,
        "name": args.name,
        "oauthClients": [args.oauthClients],
        "publicKeyEndpoint": args.publicKeyEndpoint,
        "subjectClaimName": args.subjectClaimName,
        "subjectMappingAttribute": args.subjectMappingAttribute,
        "subjectType": args.subjectType,
        "type": args.type,
        "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]
    }

    response = requests.request("POST", url, json=payload, headers=headers)
    print(response.text)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Set Token Exchange Trust')
    parser.add_argument('--url', required=True, help='URL')
    parser.add_argument('--token', required=True, help='Domain Access Token')
    parser.add_argument('--issuer', required=True, help='Issuer of the token being exchanged')
    parser.add_argument('--name', required=True, help='Name of trust configuration')
    parser.add_argument('--oauthClients', required=True, help='OAuth Clients')
    parser.add_argument('--publicKeyEndpoint', required=True, help='Public Key Endpoint, jwt URL for the issuer')
    parser.add_argument('--subjectClaimName', required=True, help='Subject Claim Name, name of the claim in the JWT that contains the subject identifier')
    parser.add_argument('--subjectMappingAttribute', required=True, help='Subject Mapping Attribute, name of the attribute in the identity domain that contains the subject identifier')
    parser.add_argument('--subjectType', required=True, help='Subject Type')
    parser.add_argument('--type', required=True, help='Type, type of trust configuration to create ( JWT or SAML)')
    args = parser.parse_args()
    set_token_exchange_trust(args)