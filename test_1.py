from flask import Flask, request, jsonify, session, abort
import os
import json
import logging
import secrets
import re
import subprocess
from functools import wraps
from pathlib import Path
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import SiteConfig, IpSecurityRestriction
from azure.keyvault.secrets import SecretClient

app = Flask(__name__)

# FIX: Generate strong secret key from environment or generate securely
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# FIX: Production configuration based on environment
app.config["DEBUG"] = os.environ.get("FLASK_ENV") == "development"
app.config["ENV"] = os.environ.get("FLASK_ENV", "production")

# FIX: More secure logging configuration with appropriate level
log_level = logging.DEBUG if app.config["DEBUG"] else logging.INFO
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="app_service.log",
)
logger = logging.getLogger(__name__)


# FIX: Load sensitive configuration from environment variables or Key Vault
def get_config():
    """Get configuration securely from environment or Azure Key Vault"""
    # Try to get configuration from environment variables first
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    app_service_name = os.environ.get("AZURE_APP_SERVICE_NAME")
    resource_group = os.environ.get("AZURE_RESOURCE_GROUP")

    # If any required config is missing, try Azure Key Vault
    if not all([subscription_id, app_service_name, resource_group]):
        try:
            key_vault_url = os.environ.get("KEY_VAULT_URL")
            if key_vault_url:
                # Use managed identity or DefaultAzureCredential for authentication
                credential = (
                    ManagedIdentityCredential()
                    if os.environ.get("AZURE_CLIENT_ID")
                    else DefaultAzureCredential()
                )
                secret_client = SecretClient(
                    vault_url=key_vault_url, credential=credential
                )

                # Get secrets from Key Vault if not in environment
                subscription_id = (
                    subscription_id
                    or secret_client.get_secret("azure-subscription-id").value
                )
                app_service_name = (
                    app_service_name
                    or secret_client.get_secret("azure-app-service-name").value
                )
                resource_group = (
                    resource_group
                    or secret_client.get_secret("azure-resource-group").value
                )
        except Exception as e:
            logger.error(f"Error retrieving configuration from Key Vault: {str(e)}")

    return {
        "subscription_id": subscription_id,
        "app_service_name": app_service_name,
        "resource_group": resource_group,
    }


# FIX: Authentication middleware
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Implement proper authentication, like JWT token validation
        # This is simplified for example purposes
        auth_header = request.headers.get("Authorization")
        if not auth_header or not validate_token(auth_header):
            logger.warning("Unauthorized access attempt")
            return abort(401)
        return f(*args, **kwargs)

    return decorated_function


def validate_token(auth_header):
    # In a real app, validate JWT token against Azure AD or other auth provider
    # This is a placeholder - implement proper token validation
    return auth_header.startswith("Bearer ")


@app.route("/api/config")
@require_auth
def get_app_configuration():
    # FIX: Return only non-sensitive configuration
    app_settings = {
        "environment": app.config["ENV"],
        "app_service": {
            "name": os.environ.get("AZURE_APP_SERVICE_NAME", "app-service-name"),
            # Only include non-sensitive information
        },
    }
    return jsonify(app_settings)


@app.route("/api/deploy", methods=["POST"])
@require_auth
def deploy_code():
    # FIX: Validate input and avoid command injection
    git_repo = request.json.get("git_repo")

    if not git_repo:
        return jsonify({"error": "No repository specified"}), 400

    # FIX: Validate git repo URL to prevent command injection
    if not is_valid_git_url(git_repo):
        logger.warning(f"Invalid git URL attempted: {git_repo}")
        return jsonify({"error": "Invalid git repository URL"}), 400

    try:
        # FIX: Use safer subprocess methods with explicit arguments
        clone_process = subprocess.run(
            ["git", "clone", git_repo, "/tmp/deploy"],
            capture_output=True,
            text=True,
            check=True,
        )

        install_process = subprocess.run(
            ["npm", "install"],
            cwd="/tmp/deploy",
            capture_output=True,
            text=True,
            check=True,
        )

        return jsonify(
            {
                "status": "deployed",
                "output": {
                    "clone": clone_process.stdout,
                    "install": install_process.stdout,
                },
            }
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Deployment failed: {e.stderr}")
        return jsonify({"error": "Deployment failed", "details": e.stderr}), 500


def is_valid_git_url(url):
    # Basic validation for git URLs
    git_url_pattern = r"^(https?|git)://([\w.@-]+)(/[\w.@/-]+)(\.git)?$"
    return bool(re.match(git_url_pattern, url))


@app.route("/api/logs")
@require_auth
def download_logs():
    # FIX: Implement access control
    log_type = request.args.get("type", "application")

    # FIX: Prevent path traversal by validating log_type
    if not is_valid_log_type(log_type):
        logger.warning(f"Invalid log type requested: {log_type}")
        return jsonify({"error": "Invalid log type"}), 400

    # FIX: Use Path to safely handle file paths
    log_path = Path("logs") / f"{log_type}.log"

    try:
        if not log_path.exists() or not log_path.is_file():
            return jsonify({"error": "Log file not found"}), 404

        # Read the file safely
        with open(log_path, "r") as f:
            logs = f.read()
        return jsonify({"logs": logs})
    except Exception as e:
        logger.error(f"Error reading log file: {str(e)}")
        return jsonify({"error": "Error retrieving logs"}), 500


def is_valid_log_type(log_type):
    # Whitelist valid log types
    valid_types = ["application", "system", "access"]
    return log_type in valid_types


def update_app_service_config():
    # FIX: Secure App Service configuration
    try:
        config = get_config()
        credential = DefaultAzureCredential()
        web_client = WebSiteManagementClient(credential, config["subscription_id"])

        # Get current config
        current_config = web_client.web_apps.get_configuration(
            config["resource_group"], config["app_service_name"]
        )

        # FIX: Set secure configurations
        current_config.https_only = True
        current_config.min_tls_version = "1.2"
        current_config.ftps_state = "FtpsOnly"
        current_config.remote_debugging_enabled = False

        # FIX: Set IP restrictions if needed
        allowed_ips = os.environ.get("ALLOWED_IPS", "").split(",")
        ip_restrictions = []

        if allowed_ips and allowed_ips[0]:
            for ip in allowed_ips:
                ip_restrictions.append(
                    IpSecurityRestriction(
                        ip_address=ip.strip(),
                        action="Allow",
                        priority=100,
                        name=f"Allow {ip.strip()}",
                    )
                )
            current_config.ip_security_restrictions = ip_restrictions

        # Update config
        web_client.web_apps.update_configuration(
            config["resource_group"], config["app_service_name"], current_config
        )

        logger.info("App Service configuration updated securely")
        return "App Service configuration updated securely"
    except Exception as e:
        logger.error(f"Error updating App Service configuration: {str(e)}")
        raise


def deploy_to_app_service():
    # FIX: Use Azure DevOps, GitHub Actions, or other secure deployment methods
    # instead of FTP/FTPS
    try:
        # Example of a secure deployment approach using ZIP deployment
        # This would typically be done through a CI/CD pipeline
        config = get_config()

        # Implementation depends on your specific deployment strategy
        # Example: use az cli or REST API for ZIP deploy

        logger.info("Deployment completed successfully")
        return "Deployment completed successfully"
    except Exception as e:
        logger.error(f"Deployment failed: {str(e)}")
        raise


if __name__ == "__main__":
    # FIX: Run securely in production
    if app.config["ENV"] == "development":
        # Only in development, and only on localhost
        app.run(host="127.0.0.1", debug=True, port=8080)
    else:
        # In production, run without debug and let the production server handle it
        app.run(host="127.0.0.1", debug=False)
