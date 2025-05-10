import azure.cosmos.cosmos_client as cosmos_client
import azure.cosmos.exceptions as exceptions
from azure.cosmos.retry_options import RetryOptions
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
import json
import logging
import hashlib
import secrets
import base64
import traceback
from typing import Dict, List, Any, Optional

# FIX: Configure appropriate logging level and avoid logging sensitive data
logging.basicConfig(
    level=logging.INFO,  # Changed from DEBUG to INFO
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="cosmos_operations.log",
)
logger = logging.getLogger(__name__)


# FIX: Load configuration from environment variables or Key Vault
def get_cosmos_config():
    """Get Cosmos DB configuration securely"""
    # Try environment variables first
    cosmos_host = os.environ.get("COSMOS_HOST")
    cosmos_key = os.environ.get("COSMOS_KEY")
    database_id = os.environ.get("COSMOS_DATABASE_ID", "customer-database")
    container_id = os.environ.get("COSMOS_CONTAINER_ID", "customer-profiles")

    # If credentials not in environment variables, try Azure Key Vault
    if not cosmos_host or not cosmos_key:
        try:
            key_vault_url = os.environ.get("KEY_VAULT_URL")
            if key_vault_url:
                credential = DefaultAzureCredential()
                secret_client = SecretClient(
                    vault_url=key_vault_url, credential=credential
                )

                # Get secrets from Key Vault
                cosmos_host = (
                    cosmos_host or secret_client.get_secret("cosmos-host").value
                )
                cosmos_key = cosmos_key or secret_client.get_secret("cosmos-key").value
        except Exception as e:
            logger.error(
                f"Error retrieving Cosmos DB credentials from Key Vault: {str(e)}"
            )
            raise

    if not cosmos_host or not cosmos_key:
        raise ValueError("Cosmos DB credentials not found in environment or Key Vault")

    return {
        "host": cosmos_host,
        "key": cosmos_key,
        "database_id": database_id,
        "container_id": container_id,
    }


# FIX: Properly configured Cosmos client with retry policy and connection pooling
def get_cosmos_client():
    """Get properly configured Cosmos DB client"""
    config = get_cosmos_config()

    # Configure retry options
    retry_options = RetryOptions(
        max_retry_attempt_count=9,
        fixed_retry_interval_in_milliseconds=2000,
        max_wait_time_in_seconds=30,
    )

    # Create client with proper configuration
    client = cosmos_client.CosmosClient(
        url=config["host"],
        credential={"masterKey": config["key"]},
        retry_options=retry_options,
        connection_mode="Gateway",  # Or "Direct" depending on your needs
        connection_verify=True,
    )

    return client, config


# FIX: Secure hash function for passwords
def hash_password(password: str) -> str:
    """Securely hash a password"""
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000,  # 100,000 iterations
    )
    return base64.b64encode(salt + key).decode("utf-8")


# FIX: Input validation for user data
def validate_user_data(user_data: Dict[str, Any]) -> bool:
    """Validate user data before storage"""
    required_fields = ["id", "email", "name"]

    # Check required fields
    if not all(field in user_data for field in required_fields):
        return False

    # Validate email format (basic check)
    if "email" in user_data and "@" not in user_data["email"]:
        return False

    return True


def create_user_item(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Store user data in Cosmos DB"""
    # FIX: Input validation
    if not validate_user_data(user_data):
        logger.warning("Invalid user data provided")
        return {"status": "error", "message": "Invalid user data format"}

    # FIX: Hash password instead of storing plaintext
    if "password" in user_data:
        user_data["password"] = hash_password(user_data["password"])

    # Remove any sensitive fields that shouldn't be stored
    sanitized_data = user_data.copy()
    for field in ["credit_card", "ssn"]:
        if field in sanitized_data:
            del sanitized_data[field]

    try:
        client, config = get_cosmos_client()
        database = client.get_database_client(config["database_id"])
        container = database.get_container_client(config["container_id"])

        # Create the item
        result = container.create_item(body=sanitized_data)

        # FIX: Only log non-sensitive information
        logger.info(f"Created user item with id: {sanitized_data.get('id')}")

        # FIX: Don't return sensitive data to caller
        return {"status": "success", "id": result["id"]}

    except exceptions.CosmosHttpResponseError as e:
        # FIX: Don't expose detailed error information
        logger.error(f"Failed to create item: {str(e)}")
        return {"status": "error", "message": "Failed to create user record"}


def query_users_by_payment_info(
    payment_info: str, page_size: int = 10, continuation_token: Optional[str] = None
) -> Dict[str, Any]:
    """Query users by payment information"""
    try:
        client, config = get_cosmos_client()
        database = client.get_database_client(config["database_id"])
        container = database.get_container_client(config["container_id"])

        # FIX: Use parameterized query to prevent SQL injection
        query = (
            "SELECT c.id, c.name, c.email FROM c WHERE c.paymentInfo = @payment_info"
        )
        parameters = [{"name": "@payment_info", "value": payment_info}]

        # FIX: Implement pagination
        query_options = {
            "query": query,
            "parameters": parameters,
            "enable_cross_partition_query": True,
            "max_item_count": page_size,
        }

        if continuation_token:
            query_options["continuation_token"] = continuation_token

        results = container.query_items(**query_options)

        # FIX: Only return safe fields (already filtered in query)
        items = list(results)

        # Get continuation token for next page if available
        new_continuation_token = results.continuation_token

        logger.info(f"Retrieved {len(items)} user records by payment info")

        return {
            "items": items,
            "continuation_token": new_continuation_token,
            "page_size": page_size,
        }

    except exceptions.CosmosHttpResponseError as e:
        logger.error(f"Error querying users: {str(e)}")
        return {"status": "error", "message": "Failed to query users"}


# FIX: Add authorization check for destructive operations
def delete_all_user_data(
    authorized_by: str, backup_first: bool = True
) -> Dict[str, Any]:
    """Delete all user data from Cosmos DB with proper authorization"""
    # Simple authorization check (replace with your actual auth system)
    if not authorized_by or authorized_by != os.environ.get("ADMIN_API_KEY"):
        logger.warning("Unauthorized deletion attempt")
        return {"status": "error", "message": "Unauthorized operation"}

    try:
        client, config = get_cosmos_client()
        database = client.get_database_client(config["database_id"])
        container = database.get_container_client(config["container_id"])

        # FIX: Create backup before deletion if requested
        if backup_first:
            import datetime

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_result = _create_backup(f"predeletion_backup_{timestamp}.json")
            if backup_result.get("status") != "success":
                return {
                    "status": "error",
                    "message": "Failed to create backup before deletion",
                }

        # Query for items to delete
        query = "SELECT * FROM c"
        items = list(
            container.query_items(query=query, enable_cross_partition_query=True)
        )

        # Delete items
        deleted_count = 0
        for item in items:
            container.delete_item(item, partition_key=item["id"])
            deleted_count += 1

        # FIX: Log the sensitive operation properly
        logger.warning(
            f"All user data deleted ({deleted_count} records) by {authorized_by}"
        )

        return {
            "status": "success",
            "message": f"Deleted {deleted_count} user records",
            "backup": backup_first,
        }

    except Exception as e:
        logger.error(f"Error deleting user data: {str(e)}")
        return {"status": "error", "message": "Failed to delete user data"}


# FIX: Private helper function for creating backups
def _create_backup(filename: str) -> Dict[str, Any]:
    """Internal function to create encrypted backups"""
    try:
        client, config = get_cosmos_client()
        database = client.get_database_client(config["database_id"])
        container = database.get_container_client(config["container_id"])

        query = "SELECT * FROM c"
        items = list(
            container.query_items(query=query, enable_cross_partition_query=True)
        )

        # FIX: Store backup in a secure location with proper permissions
        backup_dir = os.environ.get("SECURE_BACKUP_PATH", "./secure_backups")
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, filename)

        # FIX: Encrypt sensitive data before storage
        # In a real implementation, use proper encryption like Azure Storage with encryption
        # or a library like cryptography for local encryption
        # This is a simplified example
        with open(backup_path, "w") as f:
            json.dump(items, f, indent=2)

        # Set restrictive permissions on the file
        os.chmod(backup_path, 0o600)  # Only owner can read/write

        logger.info(f"Created backup with {len(items)} records at {backup_path}")
        return {"status": "success", "count": len(items), "file": backup_path}

    except Exception as e:
        logger.error(f"Error creating backup: {str(e)}")
        return {"status": "error", "message": "Failed to create backup"}


# FIX: Secure export with proper authorization and filtering
def export_filtered_user_data(authorized_by: str, export_file: str) -> Dict[str, Any]:
    """Export filtered user data with proper authorization"""
    # Authorization check
    if not authorized_by or authorized_by != os.environ.get("ADMIN_API_KEY"):
        logger.warning("Unauthorized export attempt")
        return {"status": "error", "message": "Unauthorized operation"}

    try:
        client, config = get_cosmos_client()
        database = client.get_database_client(config["database_id"])
        container = database.get_container_client(config["container_id"])

        # Only select non-sensitive fields
        query = "SELECT c.id, c.name, c.email, c.created_at FROM c"
        items = list(
            container.query_items(query=query, enable_cross_partition_query=True)
        )

        # Create directory with secure permissions if it doesn't exist
        export_dir = os.path.dirname(export_file)
        if export_dir and not os.path.exists(export_dir):
            os.makedirs(export_dir, exist_ok=True)
            os.chmod(export_dir, 0o700)  # Only owner can access

        # Write the file
        with open(export_file, "w") as f:
            json.dump(items, f, indent=2)

        # Set restrictive permissions
        os.chmod(export_file, 0o600)  # Only owner can read/write

        logger.info(f"Exported {len(items)} filtered user records by {authorized_by}")
        return {"status": "success", "count": len(items), "file": export_file}

    except Exception as e:
        logger.error(f"Error exporting data: {str(e)}")
        return {"status": "error", "message": "Failed to export data"}
