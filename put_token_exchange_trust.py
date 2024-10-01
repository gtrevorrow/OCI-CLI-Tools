import argparse
import requests
import json
import toml


def str2bool(v):
    return v.lower() in ('yes', 'true', 't', '1')


def put_token_exchange_trust(args):
    config = toml.load(args.configFile)
    url = config['url'] + "/" + args.id
    with open(args.token, 'r') as token_file:
        token = token_file.read().strip()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.26.0",
        "Authorization": "Bearer " + token
    }

    payload = {
        "active": True,
        "allowImpersonation": (config['allowImpersonation']),
        "issuer": config['issuer'],
        "name": config['name'],
        "oauthClients": [config['oauthClients']],
        "publicKeyEndpoint": config['publicKeyEndpoint'],
        "subjectClaimName": config['subjectClaimName'],
        "subjectMappingAttribute": config['subjectMappingAttribute'],
        "subjectType": config['subjectType'],
        "type": config['type'],
        "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]
    }

    if (config['allowImpersonation']):
        rules = []
        rule = {"rule":  r'workflow co gtrevorrow/oci-token-exchange-action@main',
             "ocid": "ocid1.user.oc1..aaaaaaaaiglhqgtpdqdiisskgn2idx47x2fctg6s7fhqzsbnxe6txlvof6ya"}
        rules.append(rule)
        # json_string = r'[{"rule": "workflow co \"Token\"","userId": "github"}]'
        # impersonation_service_users = json.loads(json_string)
        payload["impersonationServiceUsers"] = rules
        # clientClaimValues = ["repo:"]
        # clientClaimName = ""


    print("PUT " + payload.__str__())
    response = requests.request("PUT", url, json=payload, headers=headers)
    print(response.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Put Token Exchange Trust')
    parser.add_argument('--configFile', required=True, help='Config File')
    parser.add_argument('--token', required=True, help='Domain Access Token')
    parser.add_argument('--id', required=True, help='ID of the trust configuration')

    args = parser.parse_args()
    put_token_exchange_trust(args)
