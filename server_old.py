import selectors
import socket
import rsa
import threading
import random
import os, glob

usernames = []


class ChatServer:
    def __init__(self, host, port):
        """Initialise the server attributes."""
        self._host = host
        self._port = port
        self._th = threading.Thread(target=self._receive_message)
        self._username = None
        self._socket = None
        self._client = None
        self._pubKey, self._privKey = None, None
        self._clientkey = None
        self._read_selector = selectors.DefaultSelector()
        self._write_selector = selectors.DefaultSelector()

    def _accept_connection(self, sock):
        """Callback function for when the server is ready to accept a connection."""
        while True:
            self._client, _ = sock.accept()
            self._client.send(self._pubKey.save_pkcs1(format="DER"))
            print("Registering client...")
            self._read_selector.register(
                self._client, selectors.EVENT_READ, self._receive_message
            )
            self._write_selector.register(self._client, selectors.EVENT_WRITE)

    def _receive_message(self, sock):
        """Callback function for when a client socket is ready to receive."""
        # usernames.append(sock.recv(1024).decode("utf8"))
        Connected = True
        while Connected:
            try:
                msg = rsa.decrypt(sock.recv(1024), self._privKey).decode("ascii")
                print(msg.split(":", 1)[1])
                if (msg.split(":", 1)[1]) != "quit":
                    for key, _ in self._write_selector.select(0):
                        if key.fileobj is not sock:
                            key.fileobj.send(
                                rsa.encrypt(msg.encode("ascii"), self._clientkey)
                            )
                else:
                    Connected = False
                    break
            except Exception as e:
                print(e)
        self._client.close()

    def _init_server(self):
        """Initialises the server socket."""

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

        while True:
            for key, _ in self._read_selector.select():
                sock, callback = key.fileobj, key.data
                callback(sock)

    def generate_keys(self):
        number_start = random.randint(1, 1000)
        number_count = random.randint(1, 20)
        numbers = []
        while len(numbers) < number_count:
            numbers.append(number_start)
            number_start += 1
        for filename in glob.glob(
            f"C:/Users/antonia/Desktop/Project/server_keys/*.pem"
        ):
            os.remove(filename)
        for filename in glob.glob(
            f"C:/Users/antonia/Desktop/Project/client_keys/*.pem"
        ):
            os.remove(filename)
        for i in numbers:
            (pubKey, privKey) = rsa.newkeys(1024)
            with open(
                f"C:/Users/antonia/Desktop/Project/server_keys/pubKey{i}.pem", "wb+"
            ) as f:
                f.write(pubKey.save_pkcs1("PEM"))
            with open(
                f"C:/Users/antonia/Desktop/Project/server_keys/privKey{i}.pem", "wb+"
            ) as f:
                f.write(privKey.save_pkcs1("PEM"))
        (cpubKey, cprivKey) = rsa.newkeys(1024)
        with open(
            f"C:/Users/antonia/Desktop/Project/client_keys/pubKey{number_start}.pem",
            "wb+",
        ) as f:
            f.write(cpubKey.save_pkcs1("PEM"))
        with open(
            f"C:/Users/antonia/Desktop/Project/client_keys/privKey{number_start}.pem",
            "wb+",
        ) as f:
            f.write(cprivKey.save_pkcs1("PEM"))
        choice = random.choice(numbers)
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/pubKey{choice}.pem", "rb"
        ) as f:
            self._pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/privKey{choice}.pem", "rb"
        ) as f:
            self._privKey = rsa.PrivateKey.load_pkcs1(f.read())


if __name__ == "__main__":
    cs = ChatServer("localhost", 7342)
    cs.run()
