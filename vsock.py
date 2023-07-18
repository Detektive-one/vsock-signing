#!/usr/local/bin/env python3

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import socket
import sys
import json
from cryptography.fernet import Fernet

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
        

# Generate a random encryption key
encryption_key = "1GavmnFkL469qzY_pRqhrS7D9fiCsf7jSDLZ3vVYV1o="

#print(encryption_key.decode())
cipher_suite = Fernet(encryption_key)


def client_handler(args):
    client = VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)
    
    # User input for username and password
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    # Package the username and password into a dictionary
    credentials = {
        "username": username,
        "password": password
    }
    
    # Convert the dictionary to JSON
    json_data = json.dumps(credentials)
    
    # Encrypt the JSON data
    encrypted_data = cipher_suite.encrypt(json_data.encode())
    
    # Send the encrypted data to the server
    client.send_data(encrypted_data)
    
    # client.disconnect()  # Remove this line


def validate_credentials(credentials):
    # Existing array of credentials (replace with your own logic)
    encryption_key = "1GavmnFkL469qzY_pRqhrS7D9fiCsf7jSDLZ3vVYV1o="
    cipher_suite = Fernet(encryption_key)
    
    existing_credentials = [
        {
            "username": "admin",
            "password": "admin123"
        },
        {
            "username": "user",
            "password": "user123"
        }
    ]
    
    # Decrypt the encrypted data
    decrypted_data = cipher_suite.decrypt(credentials)
    
    # Convert the decrypted data from bytes to string
    decrypted_data = decrypted_data.decode()
    
    # Convert the JSON string to a dictionary
    credentials = json.loads(decrypted_data)
    
    # Extract the username and password from the credentials dictionary
    username = credentials.get("username")
    password = credentials.get("password")
    
    # Check if the username and password match any existing credentials
    for existing_credential in existing_credentials:
        if existing_credential["username"] == username and existing_credential["password"] == password:
            return "Login successful"
    
    return "Invalid credentials"


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
        while True:
            (from_client, (remote_cid, remote_port)) = self.sock.accept()
            # Read 1024 bytes at a time
            while True:
                try:
                    data = from_client.recv(1024)
                except socket.error:
                    break
                if not data:
                    break
                result = validate_credentials(data)
                print(result)
            from_client.close()







def server_handler(args):
    server = VsockListener()
    server.bind(args.port)
    server.recv_data()
    server.send_data()


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
