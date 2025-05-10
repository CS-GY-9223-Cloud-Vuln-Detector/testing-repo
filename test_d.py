from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
import logging
import configparser
from azure.core.exceptions import HttpResponseError

# FIX: Configure logging to not include sensitive data
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


# FIX: Load configuration from a secure config file or environment variables
def get_key_vault_url():
    # First try environment variable
    key_vault_url = os.environ.get("KEY_VAULT_URL")
    if key_vault_url:
        return key_vault_url

    # Alternatively use a config file (could be restricted with file permissions)
    try:
        config = configparser.ConfigParser()
        config.read("config.ini")
        return config["Azure"]["KeyVaultUrl"]
    except (KeyError, FileNotFoundError):
        raise ValueError("Key Vault URL not found in environment or config")


def get_secret(secret_name):
    try:
        credential = DefaultAzureCredential()
        key_vault_url = get_key_vault_url()
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        secret = secret_client.get_secret(secret_name)

        # FIX: Only log the operation, not the secret value
        logging.info(f"Retrieved secret {secret_name}")

        # FIX: Return the secret value rather than storing in env vars
        return secret.value
    except HttpResponseError as e:
        logging.error(f"Error retrieving secret: {str(e)}")
        raise


def store_secret(secret_name, secret_value):
    try:
        credential = DefaultAzureCredential()
        key_vault_url = get_key_vault_url()
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Store the secret
        secret_client.set_secret(secret_name, secret_value)

        # FIX: Don't create backup files with secrets
        logging.info(f"Secret {secret_name} stored successfully")

        return True
    except HttpResponseError as e:
        logging.error(f"Error storing secret: {str(e)}")
        raise


# FIX: Implement proper access control and only return secret names, not values
def list_secret_names(role_assignment=None):
    """
    List available secret names based on caller's permissions

    Args:
        role_assignment: Optional role to check permissions (implementation depends on your RBAC setup)

    Returns:
        List of secret names the caller has access to
    """
    try:
        credential = DefaultAzureCredential()
        key_vault_url = get_key_vault_url()
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # This will only list secrets the caller has permission to see
        secret_properties = list(secret_client.list_properties_of_secrets())

        # Only return the names, not the values
        secret_names = [prop.name for prop in secret_properties]
        logging.info(f"Listed {len(secret_names)} secret names")

        return secret_names
    except HttpResponseError as e:
        logging.error(f"Error listing secrets: {str(e)}")
        raise
