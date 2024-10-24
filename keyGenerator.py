from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Directory to store keys
private_key_dir = 'secure_keys'
public_key_dir = 'public_keys'

# Create directories if they don't exist
os.makedirs(private_key_dir, exist_ok=True)
os.makedirs(public_key_dir, exist_ok=True)

# List of users and their passphrases
users = {
    "PersonA": "my_secret_passphrase",
    "PersonB": "another_passphrase",
    "PersonC": "passphrase123",
    "PersonD": "super_secret_pass",
    "PersonE": "random_passphrase"
}

def generate_rsa_key_pair(user_id, passphrase):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key with encryption using passphrase
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )

    # Write private key to a file
    private_key_file = os.path.join(private_key_dir, f'{user_id}_private_key.pem')
    with open(private_key_file, 'wb') as f:
        f.write(private_key_pem)

    # Generate public key
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write public key to a file
    public_key_file = os.path.join(public_key_dir, f'{user_id}_public_key.pem')
    with open(public_key_file, 'wb') as f:
        f.write(public_key_pem)

    print(f"Generated keys for {user_id}:")
    print(f"Private key saved at: {private_key_file}")
    print(f"Public key saved at: {public_key_file}")

# Generate keys for all users
for user, passphrase in users.items():
    generate_rsa_key_pair(user, passphrase)

print("Key generation complete for all users.")
