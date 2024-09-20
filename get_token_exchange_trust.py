import argparse
import requests

def get_token_exchange_trust(args):
    url = args.url
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.26.0",
        "Authorization": "Bearer " + args.token
    }

    response = requests.request("GET", url, headers=headers)
    print(response.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Set Token Exchange Trust')
    parser.add_argument('--url', required=True, help='URL')
    parser.add_argument('--token', required=True, help='Domain Access Token')
    args = parser.parse_args()
    get_token_exchange_trust(args)