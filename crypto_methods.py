from eth_account.messages import encode_defunct
from eth_account import Account

def verify_signature(signature,message,address):

        # Encode the message
        message_encoded = encode_defunct(text=message)

        # Recover the address
        recovered_address = Account.recover_message(message_encoded, signature=signature)

        return address.lower() == recovered_address.lower()
