import socket
import http.client
import ssl

def vsock_proxy():
    # Listen for incoming vsock connections from the client-side (Validator Client) on 16:5000.
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, 5000))
    server.listen(1)
    print("vsock_proxy: Waiting for incoming vsock connections...")

    while True:
        conn, _ = server.accept()
        print("vsock_proxy: Accepted vsock connection")

        # Establish an internet TCP connection with the actual API on the host system
        conn_to_api = http.client.HTTPSConnection("catfact.ninja")

        # Send a GET request to the API
        conn_to_api.request("GET", "/fact")

        # Get the response from the API
        response = conn_to_api.getresponse()
        data = response.read().decode()

        # Forward the API response back to the enclave via the vsock connection
        conn.sendall(data.encode())
        conn.close()

if __name__ == "__main__":
    vsock_proxy()
