from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
import logging

# VULNERABILITY: Logging sensitive information
logging.basicConfig(level=logging.INFO)

# VULNERABILITY: Hardcoded key vault URL
KEY_VAULT_URL = "https://my-key-vault.vault.azure.net/"


def get_secret(secret_name):
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

    secret = secret_client.get_secret(secret_name)

    # VULNERABILITY: Logging secret values
    logging.info(f"Retrieved secret {secret_name}: {secret.value}")

    # VULNERABILITY: Storing secrets in environment variables
    os.environ[secret_name.upper()] = secret.value

    return secret.value


def store_secret(secret_name, secret_value):
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

    # Store the secret
    secret_client.set_secret(secret_name, secret_value)

    # VULNERABILITY: Insecure storage of secret backup
    with open(f"{secret_name}_backup.txt", "w") as f:
        f.write(secret_value)

    print(f"Secret {secret_name} stored successfully with backup")


# VULNERABILITY: No access control on who can access secrets
def get_all_secrets():
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

    secrets = {}
    for secret_properties in secret_client.list_properties_of_secrets():
        secret = secret_client.get_secret(secret_properties.name)
        secrets[secret_properties.name] = secret.value

    return secrets
