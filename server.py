import selectors, socket, rsa, threading, hashlib


clients = {}
buffer_size = 1024


class ChatServer:
    def __init__(self, host, port):
        """Initialise the server attributes."""
        self.host = host
        self.port = port
        self.th = threading.Thread(target=self.receive)
        self.username = None
        self.socket = None
        self.pubKey, self.privKey = None, None
        self.clientkey = None
        self.read_selector = selectors.DefaultSelector()
        self.write_selector = selectors.DefaultSelector()

    def accept(self, sock):
        """Callback function for when the server is ready to accept a connection."""
        client, _ = sock.accept()
        print("Registering client...")
        client.send(self.pubKey.save_pkcs1(format="DER"))
        client.send("KEY".encode("ascii"))
        stringkey = client.recv(buffer_size)
        self.clientkey = rsa.PublicKey.load_pkcs1(stringkey, format="DER")
        client.send("HASH".encode("ascii"))
        hash_clientkey = hashlib.sha256(stringkey).hexdigest()
        hashkey = client.recv(buffer_size).decode()
        if hashkey == hash_clientkey:
            print("verification successful")
            clients[client] = self.clientkey
            self.read_selector.register(client, selectors.EVENT_READ, self.receive)
            self.write_selector.register(client, selectors.EVENT_WRITE)
        else:
            print("verification failed")
            client.close()

    def receive(self, sock):
        """Callback function for when a client socket is ready to receive."""
        try:
            msg = rsa.decrypt(sock.recv(buffer_size), self.privKey).decode("ascii")
            if msg.split(":", 1)[1] != "quit":
                for key, _ in self.write_selector.select(0):
                    if key.fileobj is not sock:
                        key.fileobj.send(
                            rsa.encrypt(msg.encode("ascii"), clients[key.fileobj])
                        )
        except ConnectionResetError:
            print("client disconnected")
            self.read_selector.unregister(sock)
            self.write_selector.unregister(sock)
            del clients[sock]
            sock.close()

    def init(self):
        """Initialises the server socket."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        # Put the socket in the selector "bag":
        self.read_selector.register(
            self.socket,
            selectors.EVENT_READ,
            self.accept,
        )

    def run(self):
        """Starts the server and accepts connections indefinitely."""
        self.init()
        print("Running server...")
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/pubKey.pem", "rb"
        ) as f:
            self.pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/privKey.pem", "rb"
        ) as f:
            self.privKey = rsa.PrivateKey.load_pkcs1(f.read())
        while True:
            for key, _ in self.read_selector.select():
                sock, callback = key.fileobj, key.data
                callback(sock)


if __name__ == "__main__":
    cs = ChatServer("localhost", 7342)
    cs.run()
