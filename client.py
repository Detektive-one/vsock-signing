import socket
import ssl

def client():
    # Connect to the vsock_proxy running on the host system at 16:5000.
    conn = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    conn.connect((16, 5000))

    # Read the API response from the vsock connection and print it.
    data = conn.recv(1024).decode()
    print("Received API Response:")
    print(data)

    # Close the connection
    conn.close()

if __name__ == "__main__":
    client()
