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


#Load .env
load_dotenv()


def set_password():
    """Set system password

    Returns:
        str: Hash of the password
    """
    
    #Ask for password input
    password = input("Input Password: ")
    hash_value = hashlib.sha3_384(password.encode()).hexdigest()
    
    #Hash as often as password is long
    for _ in range(len(password)):
        hash_value = hashlib.sha3_384(hash_value.encode()).hexdigest()
    
    #Return hash
    return hash_value


#Set Password as constant
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
        
        #Decode the public key from Base58 (Solana address format) to bytes
        public_key_bytes = base58.b58decode(public_key)

        #Decode the signature from Hex to bytes
        signature_bytes = binascii.unhexlify(signature)

        #Create a VerifyKey object using the decoded public key
        verify_key = VerifyKey(public_key_bytes)

        #Verify the signature and return validity
        verify_key.verify(message.encode('utf-8'), signature_bytes)
        return True

    #If any error occurs return validity as false
    except (BadSignatureError, ValueError):
        return False


def verify_signature(signature, message, address):
    """Verify an Ethereum signature.

    Args:
        signature (str): Signature of the message.
        message (str): Message which was signed.
        address (str): Address which claims to have signed the message.

    Returns:
        bool: Confirmation of validity.
    """
    
    #Encode the message
    message_encoded = encode_defunct(text=message)

    #Recover the address
    recovered_address = Account.recover_message(message_encoded, signature=signature)
    
    #If addresses are equal signature is considered valid
    return address.lower() == recovered_address.lower()


def is_valid_eth_address(address):
    """Verifies an Ethereum address.

    Args:
        address (str): The address to be verified.

    Returns:
        bool: Confirmation of address validity.
    """
    
    #Check if address format matches the expected hex format
    if len(address) != 42 or address[:2] != "0x":
        return False
    
    #Try converting the address to integer
    try:
        int(address, 16)
    
    #If this fails define it as false
    except ValueError:
        return False
    
    return True


def generate_ec_key_pair():
    """Generates SECP256R1 keypair.

    Returns:
        tuple: (private_key, public_key)
    """
    
    #Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    #Print the result to console and return it
    print("Encoded key: ", base64.b64encode(serialize_private_key_to_string(private_key, PASSWORD).encode()).decode('utf-8')[:-1])
    return private_key, public_key


def load_keys():
    """Loads private and public keys from environment variables.

    Returns:
        tuple: (private_key, public_key) or (None, None) if an error occurs.
    """
    
    try:
        #Load the encrypted private key and decode it to utf-8
        private_key = os.getenv('private_key') + "="
        private_key = base64.b64decode(private_key.encode()).decode('utf-8')
        
        #Decrypt using the password constant
        private_key = deserialize_string_to_private_key(private_key, PASSWORD.encode())
        
    #Catch any error and print to the server logs
    except ValueError:
        print("Decryption Password is Invalid, Key Cannot be Loaded!")
        return None, None
    
    #If everything works return private and public key
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key_to_string(public_key):
    """Serializes the public key object into a string

    Args:
        public_key (Public Key): The Public key object

    Returns:
        str: Public key
    """
    
    #Serialize the public key to DER format
    der_encoded_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #Encode the DER-encoded key as Base64 and return it
    base64_encoded_key = base64.b64encode(der_encoded_key).decode('utf-8')
    return base64_encoded_key


def serialize_signature_to_string(signature):
    """Serialize signature object to string

    Args:
        signature (ECDSA signature object): The signature object

    Returns:
        str: String signature
    """
    
    #Encode the signature as Base64 and return it
    base64_encoded_signature = base64.b64encode(signature).decode('utf-8')
    return base64_encoded_signature


def deserialize_string_to_public_key(base64_encoded_key):
    """Deserialize string to Public key object

    Args:
        base64_encoded_key (string): Key to encode

    Returns:
        Public Key: The public key object
    """
    
    #Decode the Base64 string
    der_encoded_key = base64.b64decode(base64_encoded_key)

    #Load the public key from DER format and return it
    public_key = serialization.load_der_public_key(der_encoded_key, backend=default_backend())
    return public_key


def deserialize_string_to_signature(base64_encoded_signature):
    """Turns string into signature object

    Args:
        base64_encoded_signature (string): String to convert

    Returns:
        ECDSA Signature bytes: The converted signature
    """
    
    #Decode the Base64 string and return it
    signature = base64.b64decode(base64_encoded_signature)
    return signature


def deserialize_string_to_private_key(private_key_string, PASSWORD):
    """Turn string into private key object

    Args:
        private_key_string (string): The private key string to convert
        PASSWORD (string): The system password

    Returns:
        ECDSA object: The private key object
    """
    
    #Decode the PEM private key string
    pem_private_key = private_key_string.encode('utf-8')

    #Load the private key from PEM format
    private_key = serialization.load_pem_private_key(
        pem_private_key,
        password=PASSWORD,  # No password for PKCS8 private key
        backend=default_backend()  # Use the default backend
    )
    
    return private_key


def serialize_private_key_to_string(private_key, PASSWORD):
    """Serialzes a private key to string

    Args:
        private_key (ECDSA object): The key object to be converted
        PASSWORD (string): The system password

    Returns:
        String: The string verison of the private key
    """
    
    if PASSWORD:
        
        #Convert password to bytes
        password_bytes = PASSWORD.encode()
        
        #Encrypt the private key using the provided password
        encryption_algorithm = serialization.BestAvailableEncryption(password_bytes)
    else:
        
        #No encryption if password is not provided
        encryption_algorithm = serialization.NoEncryption()

    #Serialize the private key
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=encryption_algorithm).decode()


def sign_message(message):
    """Signs the message using (private_key, message) using SECP256R1.

    Returns:
        signature: The signature of the message.
    """
    
    #Load keys from memory
    private_key, public_key = load_keys()
    
    #Sign message with private key
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_bitcoin_signature(address, signature, message):
    """Verifies a taproot signature

    Args:
        address (BTC address): The address connected to the signature
        signature (taproot signature string): The taproot signature to verify
        message (String): String that was signed

    Returns:
        json: Validity
    """
    
    #Command to run the Node.js script
    command = ['node', 'verifySignature.js', address, signature, message]

    try:
        
        #Run the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        #Parse the JSON output
        output = json.loads(result.stdout)
        return output
    
    #If an error occurs log the error
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return None


def verify_signature_with_key(message, signature, public_key):
    """Verifies the ECDSA signature of a message.

    Args:
        message (str): The message that was signed.
        signature (bytes): The signature of the message.
        public_key: The public key that claims to have signed the message.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    
    try:
        
        # Deserialize the public key from the Base64 string format
        public_key = deserialize_string_to_public_key(public_key)

        # Verify the signature using the public key
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

        return True 
    
    #cATCH ANY ERRORS WHICH OCCUR
    except Exception as e:
        print(f"Verification failed: {str(e)}")
        return False  
