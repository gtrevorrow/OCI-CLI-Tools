import argparse
import requests
import json

def str2bool(v):
    return v.lower() in ('yes', 'true', 't', '1')

def patch_token_exchange_trust(args):
    url = args.url + "/" + args.id
    with open(args.token, 'r') as token_file:
        token = token_file.read().strip()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.26.0",
        "Authorization": "Bearer " + token
    }
    operations = []

    if args.active is not None:
        operations.append({"op": "replace", "path": "active", "value": args.active})
    if args.allowImpersonation is not None:
        operations.append({"op": "replace", "path": "allowImpersonation", "value": args.allowImpersonation})
    if args.issuer is not None:
        operations.append({"op": "replace", "path": "issuer", "value": args.issuer})
    if args.name is not None:
        operations.append({"op": "replace", "path": "name", "value": args.name})
    if args.oauthClients is not None:
        operations.append({"op": "replace", "path": "oauthClients", "value": [args.oauthClients]})
    if args.publicKeyEndpoint is not None:
        operations.append({"op": "replace", "path": "publicKeyEndpoint", "value": args.publicKeyEndpoint})
    if args.subjectClaimName is not None:
        operations.append({"op": "replace", "path": "subjectClaimName", "value": args.subjectClaimName})
    if args.subjectMappingAttribute is not None:
        operations.append({"op": "replace", "path": "subjectMappingAttribute", "value": args.subjectMappingAttribute})
    if args.subjectType is not None:
        operations.append({"op": "replace", "path": "subjectType", "value": args.subjectType})
    if args.type is not None:
        operations.append({"op": "replace", "path": "type", "value": args.type})
    if args.impersonationServiceUsers is not None:
        json_string = '[{"rule": "workflow co \\"Token\\"","userId": "github"}]'
        impersonation_service_users = json.loads(json_string)
        operations.append({"op": "replace", "path": "impersonationServiceUsers", "value": impersonation_service_users})

    print(operations)

    payload = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations
    }

    response = requests.request("PATCH", url, json=payload, headers=headers)
    print(response.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Set Token Exchange Trust')
    parser.add_argument('--url', required=True, help='URL')
    parser.add_argument('--token', required=True, help='Domain Access Token')
    parser.add_argument('--issuer', required=False, help='Issuer of the token being exchanged')
    parser.add_argument('--name', required=False, help='Name of trust configuration')
    parser.add_argument('--oauthClients', required=False, help='OAuth Clients')
    parser.add_argument('--publicKeyEndpoint', required=False, help='Public Key Endpoint, jwt URL for the issuer')
    parser.add_argument('--subjectClaimName', required=False,
                        help='Subject Claim Name, name of the claim in the JWT that contains the subject identifier')
    parser.add_argument('--subjectMappingAttribute', required=False,
                        help='Subject Mapping Attribute, name of the attribute in the identity domain that contains the subject identifier')
    parser.add_argument('--subjectType', required=False, help='Subject Type')
    parser.add_argument('--type', required=False, help='Type, type of trust configuration to create ( JWT or SAML)')
    parser.add_argument('--id', required=True, help='ID of the trust configuration')
    parser.add_argument('--allowImpersonation', required=False, type=str2bool, help='Allow Impersonation')
    parser.add_argument('--active', required=False, help='Active')
    parser.add_argument('--impersonationServiceUsers', required=False, help='Impersonating Service User matching rules')

    args = parser.parse_args()
    patch_token_exchange_trust(args)
