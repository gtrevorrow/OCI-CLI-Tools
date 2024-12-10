
import argparse
import requests
import json
import toml



def str2bool(v):
    return v.lower() in ('yes', 'true', 't', '1')
def set_token_exchange_trust(args):
    config = toml.load(args.configFile)
    url = config['url']
    with open(args.token, 'r') as token_file:
        token = token_file.read().strip()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.26.0",
        "Authorization": "Bearer " + token
    }
    payload = {
        "active": True,
        "allowImpersonation": str2bool(config['allowImpersonation']),
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

    if str2bool(config['allowImpersonation']):
        # json_string = r'[{"rule": "workflow co Token","ocid": "ocid1.user.oc1..aaaaaaaaiglhqgtpdqdiisskgn2idx47x2fctg6s7fhqzsbnxe6txlvof6ya"}]'
        # impersonation_service_users = json.loads(json_string)
        rules = []
        rule = {
            "rule": r'workflow_ref eq gtrevorrow/oci-token-exchange-action/.github/workflows/config.yml@refs/heads/develop',
            "ocid": "ocid1.user.oc1..aaaaaaaaiglhqgtpdqdiisskgn2idx47x2fctg6s7fhqzsbnxe6txlvof6ya"}
        rules.append(rule)
        payload["impersonationServiceUsers"] = rules

    response = requests.request("POST", url, json=payload, headers=headers)
    print(response.text)

# Example command line arguments : --token /Users/gordon/Downloads/tokens.tok --configFile config.yml
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Set Token Exchange Trust')
    parser.add_argument('--configFile', required=True, help='Config File')
    parser.add_argument('--token', required=True, help='Domain Access Token')

    args = parser.parse_args()
    set_token_exchange_trust(args)