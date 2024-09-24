const bitcoin = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');

// Function to verify a Bitcoin signature
function verifySignature(address, signature, message) {
    try {
        const isValid = bitcoinMessage.verify(message, address, signature);
        return isValid;
    } catch (e) {
        return { error: e.message };
    }
}

// Get inputs from command line arguments
const args = process.argv.slice(2);
const address = args[0];
const signature = args[1];
const message = args[2];

// Run the verification
const result = verifySignature(address, signature, message);
console.log(JSON.stringify(result)); // Output as JSON
