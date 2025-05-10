from flask import Flask, request, jsonify, session
import os
import requests
import json
import subprocess
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import SiteConfig

app = Flask(__name__)

# VULNERABILITY: Weak session secret
app.secret_key = "development-weak-key-1234"

# VULNERABILITY: Hardcoded credentials
SUBSCRIPTION_ID = "12345678-1234-1234-1234-123456789012"
APP_SERVICE_NAME = "vulnerable-app-service"
RESOURCE_GROUP = "test-resource-group"
FTP_USERNAME = "deploy-user-1"
FTP_PASSWORD = "Deploy@Password123"

# VULNERABILITY: Debug mode in production
app.config["DEBUG"] = True

# VULNERABILITY: Insecure logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="app_service.log",
)


@app.route("/api/config")
def get_app_configuration():
    # VULNERABILITY: Exposing environment variables to client
    app_settings = {
        "ENV": os.environ,
        "DEBUG": app.config["DEBUG"],
        "SECRET_KEY": app.secret_key,
        "APP_SERVICE": {
            "name": APP_SERVICE_NAME,
            "subscription": SUBSCRIPTION_ID,
            "resource_group": RESOURCE_GROUP,
        },
    }

    # VULNERABILITY: Revealing sensitive information in response
    return jsonify(app_settings)


@app.route("/api/deploy", methods=["POST"])
def deploy_code():
    # VULNERABILITY: No authentication for critical operation
    # VULNERABILITY: Command injection risk
    git_repo = request.json.get("git_repo")

    if git_repo:
        # VULNERABILITY: Unsafe command execution
        command = f"git clone {git_repo} /tmp/deploy && cd /tmp/deploy && npm install"
        output = subprocess.check_output(command, shell=True)
        return jsonify({"status": "deployed", "output": output.decode()})

    return jsonify({"error": "No repository specified"})


@app.route("/api/logs")
def download_logs():
    # VULNERABILITY: No access control
    log_type = request.args.get("type", "application")

    # VULNERABILITY: Path traversal vulnerability
    if os.path.exists(f"logs/{log_type}.log"):
        with open(f"logs/{log_type}.log", "r") as f:
            logs = f.read()
        return logs

    return jsonify({"error": "Log file not found"})


def update_app_service_config():
    # VULNERABILITY: Insecure App Service configuration
    credential = DefaultAzureCredential()
    web_client = WebSiteManagementClient(credential, SUBSCRIPTION_ID)

    # Get current config
    config = web_client.web_apps.get_configuration(RESOURCE_GROUP, APP_SERVICE_NAME)

    # VULNERABILITY: Disabling HTTPS
    config.https_only = False

    # VULNERABILITY: Setting insecure TLS version
    config.min_tls_version = "1.0"

    # VULNERABILITY: Enabling FTP deployment (insecure)
    config.ftps_state = "AllAllowed"

    # VULNERABILITY: Allowing remote debugging
    config.remote_debugging_enabled = True

    # VULNERABILITY: No IP restrictions
    config.ip_security_restrictions = []

    # Update config
    web_client.web_apps.update_configuration(RESOURCE_GROUP, APP_SERVICE_NAME, config)

    return "App Service configuration updated"


def upload_to_app_service_ftp():
    # VULNERABILITY: Using FTP instead of FTPS
    ftp_host = f"{APP_SERVICE_NAME}.scm.azurewebsites.net"
    ftp_url = f"ftp://{ftp_host}/site/wwwroot/"

    # VULNERABILITY: Hardcoded credentials in code
    files = {"file": open("app.py", "rb")}
    response = requests.put(ftp_url, files=files, auth=(FTP_USERNAME, FTP_PASSWORD))

    # VULNERABILITY: Logging detailed errors
    if response.status_code != 200:
        logging.error(f"Failed to upload: {response.text}")

    return response.status_code


if __name__ == "__main__":
    # VULNERABILITY: Running on all interfaces in debug mode
    app.run(host="0.0.0.0", debug=True, port=8080)
