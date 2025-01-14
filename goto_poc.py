import oci 
import requests
import logging
import base64
from typing import Tuple

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_client_cred_from_vault() -> str:
    """
    Retrieve client credentials from OCI vault.
    Returns: Decoded credentials string in format 'client_id:client_secret'
    """
    try:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        vault_client = oci.secrets.SecretsClient(config={}, signer=signer)
        logging.info("Retrieving client credentials from Vault")
        
        secret_bundle = vault_client.get_secret_bundle(
            secret_id='ocid1.vaultsecret.oc1.iad.amaaaaaazm7p2cyafle3qa757oe6ap6zu5tbnovauuvzdqzzxe6bjemewxpa'
        ).data.secret_bundle_content.content
        
        decoded_secret = base64.b64decode(secret_bundle).decode('utf-8')
        logging.debug("Successfully retrieved and decoded credentials")
        return decoded_secret
    except Exception as e:
        logging.error(f"Failed to retrieve credentials: {str(e)}")
        raise

def get_domain_at() -> dict:
    """
    Get domain access token using client credentials.
    Returns: Dict containing token response
    """
    client_cred = get_client_cred_from_vault()
    client_id, client_secret = client_cred.split(':')
    
    url = 'https://idcs-5d9e793985524e1c80b5d96f9a03acb7.identity.oraclecloud.com/oauth2/v1/token'
    data = {
        'grant_type': 'client_credentials',
        'scope': 'GroupAScope1',
        'client_id': client_id,
        'client_secret': client_secret
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        logging.debug(f"Requesting token from {url}")
        response = requests.post(
            url,
            data=data,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Token request failed: {str(e)}")
        raise

if __name__ == '__main__':
    try:
        token_response = get_domain_at()
        logging.info("Successfully obtained token")
        logging.debug(f"Token response: {token_response}")
    except Exception as e:
        logging.error(f"Operation failed: {str(e)}")
        raise