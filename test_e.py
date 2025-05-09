import azure.cosmos.cosmos_client as cosmos_client
import azure.cosmos.exceptions as exceptions
import json
import logging
import traceback

# VULNERABILITY: Hardcoded credentials and connection information
COSMOS_HOST = "https://test-cosmosdb.documents.azure.com:443/"
COSMOS_KEY = "Th1sIsMyS3cr3tK3yF0rC0sm0sDBwh1chSh0uldN3v3rB3H4rdc0d3d=="
DATABASE_ID = "customer-database"
CONTAINER_ID = "customer-profiles"

# VULNERABILITY: Setting up logging that might record sensitive data
logging.basicConfig(
    level=logging.DEBUG,  # Debug level logs everything
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="cosmos_operations.log",
)


def get_cosmos_client():
    # VULNERABILITY: No retry policy, no connection pooling configuration
    client = cosmos_client.CosmosClient(COSMOS_HOST, {"masterKey": COSMOS_KEY})
    return client


def create_user_item(user_data):
    """Store user data in Cosmos DB"""
    client = get_cosmos_client()
    database = client.get_database_client(DATABASE_ID)
    container = database.get_container_client(CONTAINER_ID)

    # VULNERABILITY: Storing plaintext sensitive data
    if "password" in user_data:
        # Not hashing the password before storage
        pass

    # VULNERABILITY: No input validation
    try:
        container.create_item(body=user_data)
        # VULNERABILITY: Logging sensitive information
        logging.info(f"Created user item: {json.dumps(user_data)}")
        return {"status": "success", "data": user_data}
    except exceptions.CosmosHttpResponseError as e:
        # VULNERABILITY: Exposing detailed error information
        error_details = traceback.format_exc()
        logging.error(f"Failed to create item: {error_details}")
        return {"status": "error", "error": str(e), "trace": error_details}


def query_users_by_payment_info(payment_info):
    """Query users by payment information"""
    client = get_cosmos_client()
    database = client.get_database_client(DATABASE_ID)
    container = database.get_container_client(CONTAINER_ID)

    # VULNERABILITY: Injection risk in query
    query = f"SELECT * FROM c WHERE c.paymentInfo = '{payment_info}'"

    # VULNERABILITY: No pagination, potentially returning too much data at once
    items = list(container.query_items(query=query, enable_cross_partition_query=True))

    # VULNERABILITY: Returning all fields including sensitive ones
    return items


def delete_all_user_data():
    """Delete all user data from Cosmos DB"""
    client = get_cosmos_client()
    database = client.get_database_client(DATABASE_ID)
    container = database.get_container_client(CONTAINER_ID)

    # VULNERABILITY: No authorization check for destructive operation
    # VULNERABILITY: No backup before deletion
    query = "SELECT * FROM c"
    items = list(container.query_items(query=query, enable_cross_partition_query=True))

    for item in items:
        container.delete_item(item, partition_key=item["id"])

    # VULNERABILITY: No logging for sensitive operation
    return {"status": "success", "message": f"Deleted {len(items)} user records"}


def export_all_user_data(export_file):
    """Export all user data to a local file"""
    client = get_cosmos_client()
    database = client.get_database_client(DATABASE_ID)
    container = database.get_container_client(CONTAINER_ID)

    query = "SELECT * FROM c"
    items = list(container.query_items(query=query, enable_cross_partition_query=True))

    # VULNERABILITY: Exporting sensitive data to unencrypted local file
    with open(export_file, "w") as f:
        json.dump(items, f, indent=2)

    return {"status": "success", "count": len(items), "file": export_file}
