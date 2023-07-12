import socket
import json
from eth_account import Account
from eth_account.messages import encode_defunct

def sign_transaction(private_key, transaction_payload):
    # Convert the private key to an Ethereum account
    account = Account.from_key(private_key)

    # Sign the transaction
    signed_txn = account.sign_transaction(transaction_payload)

    # Retrieve the transaction hash
    txn_hash = signed_txn.hash

    # Return the signed transaction and transaction hash
    return signed_txn.rawTransaction.hex(), txn_hash.hex()


def main():
    print("Signing server running...")

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Listen for connection from any CID
    cid = socket.VMADDR_CID_ANY

    # The port should match the client running in the EC2 server
    port = 5005

    # Bind the socket to CID and port
    s.bind((cid, port))

    # Listen for connection from EC2 server
    s.listen()

    while True:
        c, addr = s.accept()

        # Receive transaction payload and private key from EC2 server
        payload = c.recv(4096)
        payload_json = json.loads(payload.decode())

        private_key = payload_json["private_key"]
        transaction_payload = payload_json["transaction_payload"]

        try:
            # Sign the transaction inside the enclave
            signed_tx, tx_hash = sign_transaction(private_key, transaction_payload)

            # Prepare response payload
            response_payload = {
                "signed_transaction": signed_tx,
                "transaction_hash": tx_hash
            }

        except Exception as e:
            response_payload = {
                "error": str(e)
            }

        # Send the response payload back to the EC2 server
        c.send(json.dumps(response_payload).encode())
        c.close()


if __name__ == '__main__':
    main()
