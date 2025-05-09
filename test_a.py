import os
from azure.storage.blob import (
    BlobServiceClient,
    BlobClient,
    ContainerClient,
    PublicAccess,
)

# VULNERABILITY: Hardcoded connection string
connection_string = "DefaultEndpointsProtocol=https;AccountName=teststorage;AccountKey=SGVsbG8gZnJvbSBDb3BpbG90IQ=="


def create_blob_container():
    # VULNERABILITY: Insecure container access with public permissions
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.create_container(
        name="sensitive-data",
        public_access=PublicAccess.Container,  # Makes all blobs publicly accessible
    )
    print(f"Created container: {container_client.container_name}")
    return container_client


def upload_sensitive_data():
    # VULNERABILITY: No encryption for sensitive data
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("sensitive-data")

    # VULNERABILITY: Storing credentials in blobs
    password_content = "admin:password123\nuser1:secret456\nuser2:qwerty789"
    blob_client = container_client.get_blob_client("passwords.txt")
    blob_client.upload_blob(password_content, overwrite=True)

    print("Uploaded sensitive data without encryption")


# VULNERABILITY: No access controls on functions that handle sensitive operations
def delete_all_blobs():
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("sensitive-data")
    blobs = container_client.list_blobs()
    for blob in blobs:
        container_client.delete_blob(blob.name)
    print("Deleted all blobs without authorization check")


def download_blob(blob_name):
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("sensitive-data")
    blob_client = container_client.get_blob_client(blob_name)

    # VULNERABILITY: No validation of blob name
    with open(blob_name, "wb") as download_file:
        download_file.write(blob_client.download_blob().readall())
    print(f"Downloaded blob: {blob_name}")
    return "Downloaded blob: {}".format(blob_name)
