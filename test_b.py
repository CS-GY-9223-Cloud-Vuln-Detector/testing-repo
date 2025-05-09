import logging
import azure.functions as func
import subprocess
import os
import json


# VULNERABILITY: Insecure function configuration
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    # VULNERABILITY: Command injection vulnerability
    command = req.params.get("cmd")
    if command:
        # Directly executing user-provided command
        output = subprocess.check_output(command, shell=True)
        return func.HttpResponse(output)

    # VULNERABILITY: No input validation
    name = req.params.get("name")
    if name:
        return func.HttpResponse(f"Hello, {name}!")

    # VULNERABILITY: Exposing environment variables to client
    if req.method == "GET" and req.route_params.get("path") == "env":
        return func.HttpResponse(json.dumps(dict(os.environ)))

    # VULNERABILITY: Weak authentication
    auth_header = req.headers.get("Authorization")
    if auth_header == "Basic QWRtaW46UGFzc3dvcmQxMjM=":  # Admin:Password123 in base64
        return func.HttpResponse("You're authenticated!")

    return func.HttpResponse("Function executed with no input")
