from eth_account.messages import encode_defunct
from eth_account import Account
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey

def verify_signature(signature,message,address):

        # Encode the message
        message_encoded = encode_defunct(text=message)

        # Recover the address
        recovered_address = Account.recover_message(message_encoded, signature=signature)

        return address.lower() == recovered_address.lower()

def is_valid_eth_address(address):
    if len(address) != 42:
        return False
    if address[:2] != "0x":
        return False
    try:
        int(address, 16)
    except ValueError:
        return False
    return True

