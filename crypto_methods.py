#manage partial imports
from eth_account.messages import encode_defunct
from eth_account import Account

#Import crypto methods
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib
import base64

def set_password():
    password=input("Input Password: ")
    
    hash=hashlib.sha3_384(password.encode()).hexdigest()
    for i in range(len(password)):
        hash=hashlib.sha3_384(hash.encode()).hexdigest()
    
    return hash

PASSWORD=set_password()

def verify_signature(signature,message,address):
    """Verify an ethereum signature

    Args:
        signature (hex string): Signature of the message
        message (string): Message which was signed
        address (hex string): Address which claims to have signed message

    Returns:
        bool: Confirmation of validity
    """
    
    # Encode the message
    message_encoded = encode_defunct(text=message)

    # Recover the address
    recovered_address = Account.recover_message(message_encoded, signature=signature)

    return address.lower() == recovered_address.lower()

def is_valid_eth_address(address):
    """Verifies an ethereum address

    Args:
        address (hex string): The address to be verified

    Returns:
        _type_: _description_
    """
    
    #Check if address format matches the expected hex format
    if len(address) != 42:
        return False
    if address[:2] != "0x":
        return False
    
    #Try converting the address to integer
    try:
        int(address, 16)
    except ValueError:
        return False
    
    #confirm success
    return True

def generate_ec_key_pair(PASSWORD):
    """
    Generates SECP256R1 keypair
    Returns private_key, public_key
    """

    #Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    #Public key gets generated from private key
    public_key = private_key.public_key()
    
    with open("key.env",mode="w") as f:
        f.write(serialize_private_key_to_string(private_key,PASSWORD))

    return private_key, public_key

def load_keys(PASSWORD):
    
    try: 
        with open("key.env",mode="r") as f:
            private_key=deserialize_string_to_private_key(f.read(),PASSWORD.encode())
    
    except ValueError:
        print("Decryption Password is Invalid, Key Cannot be Loaded! ")
        return None, None
       
    public_key=private_key.public_key()
    
    return private_key, public_key

def serialize_public_key_to_string(public_key):
    """Turn public key to string"""
    
    # Serialize the public key to DER format
    der_encoded_key = public_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Encode the DER-encoded key as Base64
    base64_encoded_key = base64.b64encode(der_encoded_key).decode('utf-8')

    return base64_encoded_key


def serialize_signature_to_string(signature):
    """Turn signature to string"""

    #Encode the signature as Base64
    base64_encoded_signature = base64.b64encode(signature).decode('utf-8')

    return base64_encoded_signature

    
def deserialize_string_to_public_key(base64_encoded_key):
    """Turn string key to key object"""

    # Decode the Base64 string
    der_encoded_key = base64.b64decode(base64_encoded_key)

    # Load the public key from DER format
    public_key = serialization.load_der_public_key(der_encoded_key, backend=default_backend())

    return public_key


def deserialize_string_to_signature(base64_encoded_signature):
    """Turn signature to signature object"""

    # Decode the Base64 string
    signature = base64.b64decode(base64_encoded_signature)

    return signature

def deserialize_string_to_private_key(private_key_string,PASSWORD):
    """Turn string key to key object"""

    # Decode the PEM private key string
    pem_private_key = private_key_string.encode('utf-8')


    # Load the private key from PEM format
    private_key = serialization.load_pem_private_key(
        pem_private_key,
        password=PASSWORD,  # No password for PKCS8 private key
        backend=None  # Use the default backend
    )


    return private_key

def serialize_private_key_to_string(private_key, PASSWORD):
    """
    Serializes the private key to a string and encrypts it with a password.
    """
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
    """
    Signs the message using (private_key, message) using SECP256R1
    Returns signature
    """
    private_key,public_key=load_keys(PASSWORD)

    #Sign message with private key
    signature = private_key.sign(message,ec.ECDSA(hashes.SHA256()))

    return signature
