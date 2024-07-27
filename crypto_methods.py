from eth_account.messages import encode_defunct
from eth_account import Account
from dotenv import load_dotenv
import os
import requests

# Load environment variables from .env file
load_dotenv()

# Get the API key from environment variables
api_key = os.getenv('ETHERSCAN_API_KEY')

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

def get_first_transaction(address):
    page = 1
    offset = 1  # Number of transactions to fetch per page
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page={page}&offset={offset}&sort=asc&apikey={api_key}"
    response = requests.get(url)
    data = response.json()

    if data['status'] != '1' or len(data['result']) == 0:
        return None

    transactions = data['result']
    if transactions:
        return transactions[0]
