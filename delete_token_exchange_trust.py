import argparse
import requests

def delete_token_exchange_trust(args):
    url = args.url + "/" + args.id
    print(url)
    with open(args.token, 'r') as token_file:
        token = token_file.read().strip()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.26.0",
        "Authorization": "Bearer " + token
    }

    response = requests.request("DELETE", url, headers=headers)
    print(response.status_code)
    print(response.text)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Delete Token Exchange Trust')
    parser.add_argument('--url', required=True, help='URL')
    parser.add_argument('--token', required=True, help='Domain Access Token')
    parser.add_argument('--id', required=True, help='ID of the trust configuration')

    args = parser.parse_args()
    delete_token_exchange_trust(args)