import socket
import json
import os
import secrets
import argparse
import sys

class VsockStream:
    """Client"""
    def __init__(self, conn_tmo=5):
        self.conn_tmo = conn_tmo

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_data(self, data):
        """Send data to a remote endpoint"""
        self.sock.sendall(data)

    def recv_data(self):
        """Receive data from a remote endpoint"""
        while True:
            data = self.sock.recv(1024).decode()
            if not data:
                break
            print(data, end='', flush=True)
        print()

    def disconnect(self):
        """Close the client socket"""
        self.sock.close()


def send_to_signing_server(args, private_key, transaction_payload):
    client = VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)

    # Prepare payload with private key and transaction payload
    payload = json.dumps({
        "private_key": private_key,
        "transaction_payload": transaction_payload
    })

    # Send payload to the signing server
    client.send_data(payload.encode())

    # Receive response from the signing server
    response = client.recv_data(4096)

    # Close the socket connection
    client.disconnect()

    # Parse the response payload
    response_payload = json.loads(response.decode())

    if "error" in response_payload:
        # Error occurred in signing server
        print("Error occurred in signing server:", response_payload["error"])
    else:
        # Successful response
        signed_transaction = response_payload["signed_transaction"]
        transaction_hash = response_payload["transaction_hash"]

        # Use the signed transaction and transaction hash as needed
        print("Signed Transaction:", signed_transaction)
        print("Transaction Hash:", transaction_hash)



# ...

def generate_dummy_private_key():
    # Generate a random private key
    private_key = os.urandom(32).hex()
    return "0x" + private_key

def generate_dummy_transaction_payload():
    # Generate dummy values for the transaction payload
    nonce = 0
    gas_price = 20000000000
    gas_limit = 21000
    recipient = "0x" + secrets.token_hex(20)
    amount = 1000000000000000000
    data = "0x" + secrets.token_hex(32)

    transaction_payload = {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gas": gas_limit,
        "to": recipient,
        "value": amount,
        "data": data
    }

    return transaction_payload

def main():
   
    parser = argparse.ArgumentParser(prog='vsock-sample')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")
    
    client_parser = subparsers.add_parser("client", description="Client",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    client_parser.set_defaults(func=send_to_signing_server)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)

    private_key = generate_dummy_private_key()
    transaction_payload = generate_dummy_transaction_payload()

    send_to_signing_server(args, private_key, transaction_payload)
# ...

if __name__ == '__main__':
    main()
