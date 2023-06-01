import selectors
import socket
import rsa
import threading
import time


class ChatServer:
    def __init__(self, host, port):
        """Initialise the server attributes."""
        self._host = host
        self._port = port
        self._th = threading.Thread(target=self._receive_message)
        self._username = None
        self._socket = None
        self._pubKey, self._privKey = None, None
        self._clientkey = None
        self._read_selector = selectors.DefaultSelector()
        self._write_selector = selectors.DefaultSelector()

    def _accept_connection(self, sock):
        """Callback function for when the server is ready to accept a connection."""
        client, _ = sock.accept()
        print("Registering client...")
        client.send(self._pubKey.save_pkcs1(format="DER"))
        # client.send("KEY".encode("ascii"))
        # time.sleep(3)
        # self._clientkey = sock.recv(1024)
        # self._clientkey = rsa.PublicKey.load_pkcs1(self._stringkey, format="DER")
        # print(self._clientkey)
        self._read_selector.register(
            client, selectors.EVENT_READ, self._receive_message
        )
        self._write_selector.register(client, selectors.EVENT_WRITE)

    def _receive_message(self, sock):
        """Callback function for when a client socket is ready to receive."""
        msg = rsa.decrypt(sock.recv(1024), self._privKey).decode("ascii")
        print(msg.split(":", 1)[1])
        # print(msg.decode("utf8"))
        for key, _ in self._write_selector.select(0):
            if key.fileobj is not sock:
                key.fileobj.send(msg.encode("ascii"))

    def _init_server(self):
        """Initialises the server socket."""

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((self._host, self._port))
        self._socket.listen()
        # Put the socket in the selector "bag":
        self._read_selector.register(
            self._socket,
            selectors.EVENT_READ,
            self._accept_connection,
        )

    def run(self):
        """Starts the server and accepts connections indefinitely."""

        self._init_server()
        print("Running server...")
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/pubKey.pem", "rb"
        ) as f:
            self._pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/privKey.pem", "rb"
        ) as f:
            self._privKey = rsa.PrivateKey.load_pkcs1(f.read())
        # with open(
        #     f"C:/Users/antonia/Desktop/Project/client_keys/pubKey.pem", "rb"
        # ) as f:
        #     self._clientkey = rsa.PublicKey.load_pkcs1(f.read())
        while True:
            for key, _ in self._read_selector.select():
                sock, callback = key.fileobj, key.data
                callback(sock)


if __name__ == "__main__":
    cs = ChatServer("localhost", 7342)
    cs.run()
