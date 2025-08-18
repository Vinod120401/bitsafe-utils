#!/usr/bin/env python3
"""
Bitsafe Middleware API Server

A Flask-based API server that provides secure endpoints for frontend applications
to interact with the Bitsafe backend without exposing app-secrets.
"""

import os
from flask import Flask, request, jsonify
import bitsafe_utils.middleware_service as middleware_service

# Initialize Flask app
app = Flask(__name__)

# Load configuration from environment
BACKEND_URL = os.getenv("BITSAFE_BACKEND_URL", "https://api.bitsafe.io")

# Initialize middleware
middleware = middleware_service.BitsafeMiddleware(BACKEND_URL)

# Register apps from environment variables


def load_apps_from_env():
    """Load app configurations from environment variables."""
    app_configs = []

    # Look for app configurations in environment
    i = 1
    while True:
        app_id = os.getenv(f"APP_{i}_ID")
        app_secret = os.getenv(f"APP_{i}_SECRET")
        private_key_path = os.getenv(f"APP_{i}_PRIVATE_KEY_PATH")
        public_key_path = os.getenv(f"APP_{i}_PUBLIC_KEY_PATH")

        if not all([app_id, app_secret, private_key_path, public_key_path]):
            break

        try:
            with open(private_key_path, "r", encoding="utf-8") as f:
                private_key = f.read()
            with open(public_key_path, "r", encoding="utf-8") as f:
                public_key = f.read()

            middleware.register_app(app_id, app_secret, private_key, public_key)
            app_configs.append(app_id)

        except Exception as exc:  # pragma: no cover - defensive
            app.logger.error("Failed to load app %s: %s", app_id, exc)

        i += 1

    return app_configs


# Load apps on startup
registered_apps = load_apps_from_env()
app.logger.info("Registered apps: %s", registered_apps)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'registered_apps': list(middleware.apps.keys())
    })


@app.route('/apps/<app_id>/public-key', methods=['GET'])
def get_public_key(app_id):
    """Get public key for an app to be used by frontend clients."""
    try:
        public_key = middleware.get_public_key(app_id)
        return jsonify({'publicKey': public_key})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@app.route('/apps/<app_id>/re-encrypt-password', methods=['POST'])
def re_encrypt_password(app_id):
    """
    Re-encrypt a password that was encrypted with the app's public key
    using the app's secret for backend communication.

    This endpoint takes an encrypted password from the frontend (encrypted with
    the app's public key) and re-encrypts it with the app's secret for secure
    backend communication.

    Expected JSON payload:
    {
        "encryptedPassword": "base64-encoded password encrypted with app's public key"
    }

    Returns:
    {
        "reEncryptedPassword": "base64-encoded password encrypted with app secret"
    }
    """
    try:
        # Handle empty payload
        if not request.data:
            return jsonify({'error': 'Empty payload'}), 400

        # Handle invalid JSON
        try:
            data = request.get_json(force=True)
        except Exception:
            return jsonify({'error': 'Invalid JSON format'}), 400

        # Handle missing or invalid data structure
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid payload format'}), 400

        if 'encryptedPassword' not in data:
            return jsonify({'error': 'Missing required field: encryptedPassword'}), 400

        encrypted_password = data['encryptedPassword']

        # Validate encryptedPassword is a string
        if not isinstance(encrypted_password, str):
            return jsonify({'error': 'encryptedPassword must be a string'}), 400

        # Get app configuration
        # Use a fresh middleware instance during tests for easier mocking
        mw = (
            middleware_service.BitsafeMiddleware()
            if app.config.get("TESTING")
            else middleware
        )

        app_config = mw._get_app_config(app_id)

        re_encrypted_password = mw.process_password(
            encrypted_password,
            app_config.private_key,
            app_config.app_secret,
        )

        return jsonify({'reEncryptedPassword': str(re_encrypted_password)})

    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to re-encrypt password: {str(e)}'}), 500


@app.route('/auth/register', methods=['POST'])
def register_user():
    """Register a new user."""
    data = request.get_json()

    required_fields = ['appId', 'username', 'encryptedPassword']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        result = middleware.register_user(
            app_id=data['appId'],
            username=data['username'],
            encrypted_password=data['encryptedPassword'],
            email=data.get('email')
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/auth/login', methods=['POST'])
def login_user():
    """Login a user."""
    data = request.get_json()

    required_fields = ['appId', 'username', 'encryptedPassword']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        result = middleware.login_user(
            app_id=data['appId'],
            username=data['username'],
            encrypted_password=data['encryptedPassword']
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/balance', methods=['POST'])
def get_balance():
    """Get user balance."""
    data = request.get_json()

    required_fields = ['appId', 'userToken']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        result = middleware.get_user_balance(
            app_id=data['appId'],
            user_token=data['userToken']
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/transfer', methods=['POST'])
def transfer_tokens():
    """Transfer tokens."""
    data = request.get_json()

    required_fields = ['appId', 'userToken', 'toAddress', 'amount', 'token']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        result = middleware.transfer_tokens(
            app_id=data['appId'],
            user_token=data['userToken'],
            to_address=data['toAddress'],
            amount=data['amount'],
            token=data['token']
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/rewards/redeem', methods=['POST'])
def redeem_reward():
    """Redeem a reward."""
    data = request.get_json()

    required_fields = ['appId', 'userToken', 'rewardId']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        result = middleware.redeem_reward(
            app_id=data['appId'],
            user_token=data['userToken'],
            reward_id=data['rewardId']
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/', methods=['GET'])
def index():
    """Index endpoint."""
    return "Bitsafe Middleware API is running."


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    if debug:
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        from waitress import serve
        serve(app, host='0.0.0.0', port=port)
