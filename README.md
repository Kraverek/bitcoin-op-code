# Taproot Wizard Quantum Cats

## Project Description

In the spirit of the Taproot Wizard Quantum Cats competition and to honor the Bitcoin OP_CAT operator, I've cooked up an app that lets you add OP_CAT as a PROVABLY_UNSPENDABLE output. This nifty trick makes the operator visible on mempool.space, opening the door to some wild experiments and fun. What's more, the app enables you to include messages along with the OP_RETURN operator, allowing you to embed custom strings in your transactions. Dive into the fun now and start embedding your own messages with OP_RETURN!

## Installation

1. Clone the repository:
```
git clone https://github.com/Kraverek/bitcoin-op-code
cd bitcoin-op-code
```
2. Build the app:

**Important**: Ensure you have Go version 1.21.5 or 1.21.6 installed before proceeding.
Build the application by running:
```
go build
```
3. Run the compiled executable

Execute the following command to run the application:
```
./bitcoin-op-code
```
This will start the server on port 7777, making all endpoints available for use.

4.  Install Postman and Import Collection

Download and install Postman for interacting with the application. Import the endpoint collection from the following location to get started: **/postman/bitcoin-op-code.postman_collection.json**

## Usage Examples

Interaction with the app is a breeze with Postman using the provided endpoints. You'll find features like wallet creation, listing unspent transaction outputs (UTXOs), sending UTXOs, and adding OP_CAT and OP_RETURN to transactions.

## Important Note on Transaction Fees

When using this application on the Bitcoin mainnet, it is crucial to set an appropriate fee rate to ensure your transactions are processed in a timely manner. The default fee rate is set to 1 sat/vB, which is generally sufficient for testnet transactions. However, this rate might not be adequate for mainnet, especially during times of high network congestion.

Below is an example configuration for a transaction. Make sure to set the `"network"` to `"mainnet"` and adjust the `"fee_rate"` accordingly based on the current network conditions.

```json
{
    "private_key": "your_private_key_here",
    "utxos": [
        "utxo1",
        "utxo2"
    ],
    "destinations": [{
        "address": "recipient_address",
        "value": 546
    }],
    "fee_rate": 60, // Adjust this value based on current network conditions
    "network": "mainnet",
    "use_api": true
}
```

## License

This project rocks the MIT License. Check out the full license here: [MIT License](https://opensource.org/licenses/MIT).

## Support and Collaboration

Got questions or need a hand with something? I'm here to help out! If you've got some cool ideas to jazz up the project or just want to chat about potential collabs, feel free to drop a line.

## Important: Caution and Safety

As you explore and utilize this software, **I strongly urge you to exercise extreme caution** – particularly when it comes to dealing with real bitcoins. Here are some key points to keep in mind:

- **Start with a Test Environment**: Before using the software with real bitcoins, begin by testing all its functionalities in a safe test environment, like the Bitcoin Testnet. This will allow you to understand how the system works without the risk of losing actual funds.

- **Understanding Functions**: Ensure that you fully understand how each function of the software works before using it in a production environment. If in doubt, seek assistance in the documentation or ask questions in the community.

- **Caution with Seeds and Private Keys**: Be especially careful when dealing with seeds and private keys. Exposing this information to third parties or losing it can lead to irreversible loss of your assets.

- **Experimental Nature**: Keep in mind that the software might be of an experimental nature and is not free from potential errors. Use it at your own risk.

- **Updates and Changes**: Stay updated with any software updates and changes. New versions may contain important security fixes and functionality improvements.

Adhering to these guidelines can greatly enhance your safety while exploring the capabilities offered by this software. Security and risk awareness should always be your top priority!
