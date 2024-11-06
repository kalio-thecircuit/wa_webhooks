from flask import Flask, request
import hmac
import hashlib
import logging
import os
from google.cloud import secretmanager
import json

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_secret_value(secret_id: str) -> str:
    """Retrieve secret value from Google Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    project_id = os.getenv("the-circuit-2f8bd") 
    
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

# Initialize Flask app and get secrets
app = Flask(__name__)

try:
    VERIFY_TOKEN = get_secret_value("webhook-verify-token")
    APP_SECRET = get_secret_value("webhook-app-secret")
except Exception as e:
    logger.error(f"Failed to retrieve secrets: {str(e)}")
    raise

# Get port from environment variable
port = int(os.environ.get('PORT', 8080))

@app.route('/webhooks', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        if (request.args.get('hub.mode') == 'subscribe' and 
            request.args.get('hub.verify_token') == VERIFY_TOKEN):
            return request.args.get('hub.challenge')
        return 'Failed verification', 403
    
    # Handle POST requests
    signature = request.headers.get('X-Hub-Signature-256', '').split('sha256=')[-1]
    expected_signature = hmac.new(
        APP_SECRET.encode(), 
        request.data, 
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        return 'Invalid signature', 403

    # Handle the message
    try:
        data = json.loads(request.data)
        if data['object'] == 'whatsapp_business_account':
            for entry in data['entry']:
                for change in entry['changes']:
                    if change['value'].get('messages'):
                        message = change['value']['messages'][0]
                        logger.info(f"Received message: {message['text']['body']}")
        return 'OK', 200
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        return 'Error processing message', 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=port)

