# Swupel Primain Service

Swupel Primain service aims to provide a simple alternative to long and complicated cryptographical addresses.
These shortened addresses are referred to as Primains.

## Legal notice
The working mechanism behind Primains is protected by a provisional patent, upon which any infringement will be prosecuted.
If you are interested in improving the spread of this innovation, feel free to contact us at ``info@swupelpms.com ``.
As this code might be open-sourced in the future, any and all feedback is appreciated. 

## Working mechanism
Primains are stored in a table alongside their corresponding address and a proof.
This proof, which is a cryptographic signature on the custom primain and the address it's linked to, 
ensures only the owners of an address can create a primain that links to said address.

This mechanism also allows users to verify that the address they are being shown has not been manipulated in any way.
As an extra layer of security, swupel will soon sign all primains, to make man-in-the-middle attacks impossible.

## Security 
Primain security is not derived from trust in a central entity (Swupel) or a decentralized network of nodes,
but from the nature of cryptographic signatures. As long as modern asymmetric cryptography remains as secure as it is, Swupel Primains will remain secure, too.
All users are advised to cross-verify the validity of both of the two involved signatures.

## Running the service locally
Start by installing the requirements by running ``pip install -r requirements.txt`` or, for Linux users, by running ``pip3 install -r requirements.txt``.
Then run the app.py file.

## Further information
For further information, consult the docs folder or write us an email at ``info@swupelpms.com``.