import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os

app = Flask(__name__)

# Directories to store uploads and signed files
UPLOAD_FOLDER = 'uploads'
SIGNED_FOLDER = 'signed'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# Helper function to get private key
def get_private_key(user_id, passphrase):
    print(f"Fetching private key for {user_id}")
    private_key_path = f'secure_keys/{user_id}_private_key.pem'
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase.encode(),
        )
    return private_key

# Helper function to get public key
def get_public_key(user_id):
    print(f"Fetching public key for {user_id}")
    public_key_path = f'secure_keys/{user_id}_public_key.pem'
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Endpoint to sign a JSON file and save to 'signed/' folder
@app.route('/api/sign', methods=['POST'])
def sign_json_file():
    try:
        # Check if a file is part of the request
        if 'file' not in request.files:
            print("No file provided in the request")
            return jsonify({'error': 'No file provided.'}), 400

        # Get file, signer, and passphrase from the request
        file = request.files['file']
        signer = request.form.get('signer')
        passphrase = request.form.get('passphrase')

        if not signer or not passphrase:
            print("Missing signer or passphrase")
            return jsonify({'error': 'Missing signer or passphrase.'}), 400

        # Save the uploaded file temporarily
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        print(f"File saved to {filepath}")

        # Load the JSON content from the file
        try:
            with open(filepath, 'r') as f:
                json_data = json.load(f)
            print("JSON file loaded successfully")
        except json.JSONDecodeError:
            print("Invalid JSON file")
            return jsonify({'error': 'Invalid JSON file.'}), 400

        # Add the signer to the JSON data
        json_data['signed_by'] = signer

        # Canonicalize JSON for signing
        json_string = json.dumps(json_data, sort_keys=True)

        # Get the private key for signing
        try:
            private_key = get_private_key(signer, passphrase)
        except Exception as e:
            print(f"Error loading private key: {str(e)}")
            return jsonify({'error': f'Error loading private key: {str(e)}'}), 500

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
            print("JSON signed successfully")
        except Exception as e:
            print(f"Signing failed: {str(e)}")
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

        # Save the signed JSON to the 'signed/' folder
        signed_file_path = os.path.join(SIGNED_FOLDER, f"signed_{file.filename}")
        with open(signed_file_path, 'w') as signed_file:
            json.dump(json_data, signed_file, indent=4)
        print(f"Signed JSON saved to {signed_file_path}")

        return jsonify({
            'message': 'JSON successfully signed and saved to the signed folder.',
            'signed_json': json_data,             # Send signed JSON in response
            'signed_file_path': signed_file_path  # Path to saved signed file
        }), 200

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({'error': 'An internal server error occurred.'}), 500

# Start the Flask app
if __name__ == '__main__':
    print("Starting Flask app")
    app.run(debug=True)

