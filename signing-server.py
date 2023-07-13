import socket
import json
from eth_account import Account
from eth_account.messages import encode_defunct


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


def sign_transaction(private_key, transaction_payload):
    # Convert the private key to an Ethereum account
    account = Account.from_key(private_key)

    # Sign the transaction
    signed_txn = account.sign_transaction(transaction_payload)

    # Retrieve the transaction hash
    txn_hash = signed_txn.hash

    # Return the signed transaction and transaction hash
    return signed_txn.rawTransaction.hex(), txn_hash.hex()

def send_ec2_server(payload,server):
    
   
    

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
        
        server.send_data(json.dumps(response_payload).encode())
        

def main():
    print("Signing server running...")    
    port = 5005

    server = VsockListener()
    server.bind(socket.VMADDR_CID_ANY,port)  
    payload = server.recv_data(4096)

    send_ec2_server(payload,server)


if __name__ == '__main__':
    main()
