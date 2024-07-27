#manage partial imports
from eth_account.messages import encode_defunct
from eth_account import Account


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
