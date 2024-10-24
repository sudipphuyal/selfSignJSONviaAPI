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
PRIVATE_KEYS_FOLDER = 'secure_keys'   # Private keys folder
PUBLIC_KEYS_FOLDER = 'public_keys'    # Public keys folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# Helper function to get private key from the secure_keys folder
def get_private_key(user_id, passphrase):
    print(f"Fetching private key for {user_id}")
    private_key_path = os.path.join(PRIVATE_KEYS_FOLDER, f'{user_id}_private_key.pem')
    
    if not os.path.exists(private_key_path):
        print(f"Private key file not found: {private_key_path}")
        raise FileNotFoundError(f"Private key file not found: {private_key_path}")
    
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase.encode(),
        )
    return private_key

# Helper function to get public key from the public_keys folder
def get_public_key(user_id):
    print(f"Fetching public key for {user_id}")
    public_key_path = os.path.join(PUBLIC_KEYS_FOLDER, f'{user_id}_public_key.pem')
    
    if not os.path.exists(public_key_path):
        print(f"Public key file not found: {public_key_path}")
        raise FileNotFoundError(f"Public key file not found: {public_key_path}")
    
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

        print(f"Signer: {signer}, Passphrase: {passphrase}")

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

# Endpoint to verify a signed JSON file
@app.route('/api/verify', methods=['POST'])
def verify_json_file():
    try:
        # Check if a file is part of the request
        if 'file' not in request.files:
            print("No file provided in the request")
            return jsonify({'error': 'No file provided.'}), 400

        # Get the uploaded signed file
        file = request.files['file']
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        print(f"File saved to {filepath}")

        # Load the signed JSON content from the file
        try:
            with open(filepath, 'r') as f:
                signed_json_data = json.load(f)
            print("Signed JSON file loaded successfully")
        except json.JSONDecodeError:
            print("Invalid JSON file")
            return jsonify({'error': 'Invalid JSON file.'}), 400

        # Extract signer, signature, and public key
        signer = signed_json_data.get('signed_by')
        signature_hex = signed_json_data.pop('signature', None)
        public_key_pem = signed_json_data.pop('public_key', None)

        if not signature_hex or not public_key_pem:
            print("Missing signature or public key in the JSON.")
            return jsonify({'error': 'Missing signature or public key.'}), 400

        print(f"Signer: {signer}, Signature: {signature_hex}")

        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            print("Invalid signature format")
            return jsonify({'error': 'Invalid signature format.'}), 400

        # Re-canonicalize the JSON data (without signature and public key) for verification
        json_string = json.dumps(signed_json_data, sort_keys=True)

        # Load the public key
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            print(f"Failed to load public key: {str(e)}")
            return jsonify({'error': f'Failed to load public key: {str(e)}'}), 500

        # Verify the signature
        try:
            public_key.verify(
                signature,
                json_string.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"Signature is valid. Signed by {signer}.")
            return jsonify({'message': f'Signature is valid. Signed by {signer}.'}), 200
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")
            return jsonify({'error': f'Signature verification failed: {str(e)}'}), 400

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({'error': 'An internal server error occurred.'}), 500

# Start the Flask app
if __name__ == '__main__':
    print("Starting Flask app")
    app.run(debug=True)
