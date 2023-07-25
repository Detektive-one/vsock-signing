import socket
import ssl

def client(cid, port):
    # Connect to the vsock_proxy running on the host system at the specified CID and port.
    conn = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    conn.connect((cid, port))

    # Read the API response from the vsock connection and print it.
    data = conn.recv(1024).decode()
    print("Received API Response:")
    print(data)

    # Close the connection
    conn.close()

if __name__ == "__main__":
    cid = int(input("Enter the CID of the vsock_proxy: "))
    port = int(input("Enter the port number of the vsock_proxy: "))
    client(cid, port)
