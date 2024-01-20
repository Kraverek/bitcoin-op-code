# Taproot Wizard Quantum Cats

## Project Description

In the spirit of the Taproot Wizard Quantum Cats competition and to honor the Bitcoin OP_CAT operator, I've cooked up an app that lets you add OP_CAT as a PROVABLY_UNSPENDABLE output. This nifty trick makes the operator visible on mempool.space, opening the door to some wild experiments and fun. What's more, the app enables you to include messages along with the OP_RETURN operator, allowing you to embed custom strings in your transactions. Dive into the fun now and start embedding your own messages with OP_RETURN!

## Installation

1. Clone the repository:
git clone [Your Repository URL]
2. Build the app:
go build
3. Run the compiled `.exe` file:
./bitcoin-op-code.exe

This fires up the server on port 7777, with all endpoints ready for action.

4. Install Postman and import the endpoint collection to start playing with the app.

## Usage Examples

Interaction with the app is a breeze with Postman using the provided endpoints. You'll find features like wallet creation, listing unspent transaction outputs (UTXOs), sending UTXOs, and adding OP_CAT and OP_RETURN to transactions.

## License

This project rocks the MIT License. Check out the full license here: [MIT License](https://opensource.org/licenses/MIT).

## Support and Collaboration

Got questions or need a hand with something? I'm here to help out! If you've got some cool ideas to jazz up the project or just want to chat about potential collabs, feel free to drop a line.
