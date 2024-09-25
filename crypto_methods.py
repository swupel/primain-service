# Manage partial imports
from eth_account.messages import encode_defunct
from eth_account import Account
from dotenv import load_dotenv

# Import crypto methods
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


#Full imports
import subprocess
import binascii
import hashlib
import base64
import base58
import json
import os



load_dotenv()

def set_password():
    password = input("Input Password: ")
    hash_value = hashlib.sha3_384(password.encode()).hexdigest()
    
    for _ in range(len(password)):
        hash_value = hashlib.sha3_384(hash_value.encode()).hexdigest()
    
    return hash_value

PASSWORD = set_password()


def verify_solana_signature(signature, message, public_key):
    """Verify a Solana Ed25519 signature.
    
    Args:
        signature (str): Hex-encoded signature of the message.
        message (str): Message that was signed.
        public_key (str): Base58-encoded Solana public key (address) that claims to have signed the message.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Decode the public key from Base58 (Solana address format) to bytes
        public_key_bytes = base58.b58decode(public_key)

        # Decode the signature from Hex to bytes
        signature_bytes = binascii.unhexlify(signature)

        # Create a VerifyKey object using the decoded public key
        verify_key = VerifyKey(public_key_bytes)

        # Verify the signature
        verify_key.verify(message.encode('utf-8'), signature_bytes)

        return True  # Signature is valid

    except (BadSignatureError, ValueError):
        return False  # Invalid signature or other errors

def verify_signature(signature, message, address):
    """Verify an Ethereum signature.

    Args:
        signature (str): Signature of the message.
        message (str): Message which was signed.
        address (str): Address which claims to have signed the message.

    Returns:
        bool: Confirmation of validity.
    """
    # Encode the message
    
    message_encoded = encode_defunct(text=message)

    # Recover the address
    recovered_address = Account.recover_message(message_encoded, signature=signature)

    return address.lower() == recovered_address.lower()

def is_valid_eth_address(address):
    """Verifies an Ethereum address.

    Args:
        address (str): The address to be verified.

    Returns:
        bool: Confirmation of address validity.
    """
    # Check if address format matches the expected hex format
    if len(address) != 42 or address[:2] != "0x":
        return False
    
    # Try converting the address to integer
    try:
        int(address, 16)
    except ValueError:
        return False
    
    return True

def generate_ec_key_pair():
    """Generates SECP256R1 keypair.

    Returns:
        tuple: (private_key, public_key)
    """
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    print("Encoded key: ", base64.b64encode(serialize_private_key_to_string(private_key, PASSWORD).encode()).decode('utf-8')[:-1])
    return private_key, public_key

def load_keys():
    """Loads private and public keys from environment variables.

    Returns:
        tuple: (private_key, public_key) or (None, None) if an error occurs.
    """
    try:
        private_key = os.getenv('private_key') + "="
        private_key = base64.b64decode(private_key.encode()).decode('utf-8')
        private_key = deserialize_string_to_private_key(private_key, PASSWORD.encode())
    except ValueError:
        print("Decryption Password is Invalid, Key Cannot be Loaded!")
        return None, None
       
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key_to_string(public_key):
    """Turns public key to string."""
    # Serialize the public key to DER format
    der_encoded_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encode the DER-encoded key as Base64
    base64_encoded_key = base64.b64encode(der_encoded_key).decode('utf-8')
    return base64_encoded_key

def serialize_signature_to_string(signature):
    """Turns signature to string."""
    # Encode the signature as Base64
    base64_encoded_signature = base64.b64encode(signature).decode('utf-8')
    return base64_encoded_signature

def deserialize_string_to_public_key(base64_encoded_key):
    """Turns string key to key object."""
    # Decode the Base64 string
    der_encoded_key = base64.b64decode(base64_encoded_key)

    # Load the public key from DER format
    public_key = serialization.load_der_public_key(der_encoded_key, backend=default_backend())
    return public_key

def deserialize_string_to_signature(base64_encoded_signature):
    """Turns signature to signature object."""
    # Decode the Base64 string
    signature = base64.b64decode(base64_encoded_signature)
    return signature

def deserialize_string_to_private_key(private_key_string, PASSWORD):
    """Turns string key to key object."""
    # Decode the PEM private key string
    pem_private_key = private_key_string.encode('utf-8')

    # Load the private key from PEM format
    private_key = serialization.load_pem_private_key(
        pem_private_key,
        password=PASSWORD,  # No password for PKCS8 private key
        backend=default_backend()  # Use the default backend
    )
    return private_key

def serialize_private_key_to_string(private_key, PASSWORD):
    """Serializes the private key to a string and encrypts it with a password."""
    if PASSWORD:
        # Convert password to bytes
        password_bytes = PASSWORD.encode()
        # Encrypt the private key using the provided password
        encryption_algorithm = serialization.BestAvailableEncryption(password_bytes)
    else:
        # No encryption if password is not provided
        encryption_algorithm = serialization.NoEncryption()

    # Serialize the private key
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm
    ).decode()

def sign_message(message):
    """Signs the message using (private_key, message) using SECP256R1.

    Returns:
        signature: The signature of the message.
    """
    private_key, public_key = load_keys()
    # Sign message with private key
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def verify_bitcoin_signature(address, signature, message):
    # Command to run the Node.js script
    command = ['node', 'verifySignature.js', address, signature, message]

    try:
        # Run the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parse the JSON output
        output = json.loads(result.stdout)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return None

