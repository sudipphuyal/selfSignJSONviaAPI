import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function to get private key
def get_private_key(user_id, passphrase):
    private_key_path = f'secure_keys/{user_id}_private_key.pem'
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase.encode(),
        )
    return private_key

# Helper function to get public key
def get_public_key(user_id):
    public_key_path = f'public_keys/{user_id}_public_key.pem'
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

@app.route('/api/sign', methods=['POST'])
def sign_json():
    """API to sign a JSON file."""
    data = request.json
    signer = data.get('signer')
    passphrase = data.get('passphrase')
    json_data = data.get('json')

    if not signer or not passphrase or not json_data:
        return jsonify({'error': 'Missing signer, passphrase, or JSON data.'}), 400

    # Add the signer to the JSON data
    json_data['signed_by'] = signer

    # Canonicalize JSON for signing
    json_string = json.dumps(json_data, sort_keys=True)

    # Get the private key for signing
    try:
        private_key = get_private_key(signer, passphrase)
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve private key: {str(e)}'}), 500

    # Sign the JSON data
    try:
        signature = private_key.sign(
            json_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        return jsonify({'error': f'Signing failed: {str(e)}'}), 500

    # Get the public key and add it to the JSON
    public_key = get_public_key(signer)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Add signature and public key to the JSON
    json_data['signature'] = signature.hex()
    json_data['public_key'] = public_key_pem

    return jsonify({
        'message': 'JSON successfully signed.',
        'signed_json': json_data
    }), 200
