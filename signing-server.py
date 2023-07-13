import socket
import json
import secrets
import argparse
import sys

from eth_account import Account


def generate_dummy_private_key():
    # Generate a random private key
    private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    return private_key

def generate_dummy_transaction_payload():
    # Generate dummy values for the transaction payload
    nonce = 0
    gas_price = 20000000000
    gas_limit = 21000
    recipient = "0x1234567890123456789012345678901234567890"
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

def createPayload():

    private_key = generate_dummy_private_key()
    transaction_payload = generate_dummy_transaction_payload()
    
    # Prepare payload with private key and transaction payload
    payload = json.dumps({
        "private_key": private_key,
        "transaction_payload": transaction_payload
    })

    return payload

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
                #print("error)
                break
            print(data, end='', flush=True)
        print()
        return data

    def disconnect(self):
        """Close the client socket"""
        self.sock.close()


def client_handler(args):
    client = VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)
    msg = createPayload()
    client.send_data(msg.encode())
    response = client.recv_data()
    
    client.disconnect()
    
    #response_data = json.loads(response)
    print(response)

def sign_transaction(private_key, transaction_payload):
    # Convert the private key to an Ethereum account
    account = Account.from_key(private_key)

    # Sign the transaction
    signed_txn = account.sign_transaction(transaction_payload)

    # Retrieve the transaction hash
    txn_hash = signed_txn.hash

    # Return the signed transaction and transaction hash
    return signed_txn.rawTransaction.hex(), txn_hash.hex()

def send_ec2_server(payload):   
    payload_json = json.loads(payload)
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
        print(response_payload)
	
        return response_payload
       

    except Exception as e:
        response_payload = {
            "error": str(e)
        }

        return response_payload

        
        

class VsockListener:
    """Server"""
    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog

    def bind(self, port):
        """Bind and listen for connections on the specified port"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        """Receive data from a remote endpoint"""
        received_data = b""
        while True:
            (from_client, (remote_cid, remote_port)) = self.sock.accept()

            while True:
                try:
                    data = from_client.recv(1024)
                except socket.error:
                    break
                if not data:
                    break
                received_data += data

            from_client.close()
            return received_data

    def send_data(self, data):
        """Send data to a renote endpoint"""
        while True:
            (to_client, (remote_cid, remote_port)) = self.sock.accept()
            to_client.sendall(data)
            to_client.close()


def server_handler(args):
    server = VsockListener()
    server.bind(args.port)
    payload = server.recv_data()

    data = send_ec2_server(payload)
    #server.send_data(("hello").encode())
    server.send_data(json.dumps(data).encode())


    
    

def main():
    parser = argparse.ArgumentParser(prog='signing-server')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("client", description="Client",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    client_parser.set_defaults(func=client_handler)

    server_parser = subparsers.add_parser("server", description="Server",
                                          help="Listen on a given port.")
    server_parser.add_argument("port", type=int, help="The local port to listen on.")
    server_parser.set_defaults(func=server_handler)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
    
