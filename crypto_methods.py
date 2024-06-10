from eth_account.messages import encode_defunct
from eth_account import Account
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey
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
import requests

import requests
import requests

def get_tx_by_index(block_index,tx_index):
    # API parameters
    api_url = "https://api.etherscan.io/api"
    block_number = hex(block_index)# Example block number in hexadecimal
    transaction_index = hex(tx_index) # Example transaction index in hexadecimal

    # Constructing the URL
    url_params = {
        "module": "proxy",
        "action": "eth_getTransactionByBlockNumberAndIndex",
        "tag": block_number,
        "index": transaction_index,
        "apikey": api_key,
    }

    # Making the request
    response = requests.get(api_url, params=url_params)

    # Parsing the response
    try:
        if response.status_code == 200:
            data = response.json()
            if data["result"]["to"]:
                return data["result"]["to"]
    except TypeError:
        pass
        
    return None


from json import loads
def load_words():
    '''Loads a list of words from a file, these will be used as the basis for the Primains'''
    path='10kwords.txt'

    with open(path, mode='r') as f:
        try:
            w=f.read()
            words=loads(w)
        except(OSError):
            pass
    return words

WORDS=load_words()

def get_index_from_prim_(prim,num=False):

    #Replacing each word in the primain by its 
    # wordlist index and joining them into the Primain number
    if not num:
        try:
            prilist=prim.split('.')
        
            pri1=str(WORDS.index(prilist[0]))
            pri2=str(WORDS.index(prilist[1]))
            pri3=str(WORDS.index(prilist[2]))
        except(ValueError,AttributeError):
            return None,None
        while len(pri3) < 4:
            pri3='0'+str(pri3)
        while len(pri2) < 4:
            pri2='0'+str(pri2)
        while len(pri1) < 4:
            pri1='0'+str(pri1)
        primnumber=pri1+pri2+pri3
    else:
        primnumber=str(prim)

    #Taking the transaction and block index values 
    # from the Primain number
    txindex=int(primnumber[-4:])
    blocknumber=int(primnumber[0:-4])
    return blocknumber,txindex
    

def generate_primain(tx_index,block_index,num=False):
    #Adding zeros in front of numbers smaller than 1000 
    # to ensure proper formating
    try:
        while len(str(tx_index)) < 4:
            tx_index=f'{0}{tx_index}'
        while len(str(block_index)) < 8:
            block_index=f'{0}{block_index}'
        #Creating the primain number
        primain_number=f'{block_index}{tx_index}'
        if num:
            return primain_number
        #Splitting the number in 4 digits long parts
        parts = [int(primain_number[i:i+4]) 
                for i in range(0, len(primain_number), 4)]

        #Replacing the numbers with the Wordlist words 
        # (removing any capitalisations)
        for c,number in enumerate(parts):
            parts[c]=WORDS[int(parts[c])]
        #Combining the list of 3 words into a Primain 
        primain='.'.join(parts)
    except:
        return None
    
    return primain
