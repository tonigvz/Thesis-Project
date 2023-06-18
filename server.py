import selectors, socket, rsa, threading, hashlib, os


clients = {}
buffer_size = 2048


class ChatServer:
    def __init__(self, host, port):
        """Initializare atribute server."""
        self.host = host
        self.port = port
        self.th = threading.Thread(target=self.receive)
        self.username = None
        self.socket = None
        self.pubKey, self.privKey = None, None
        self.clientkey = None
        self.read_selector = selectors.DefaultSelector()
        self.write_selector = selectors.DefaultSelector()

    def init(self):
        """Initializeaza socket-ul serverului."""
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
        """Pornește serverul și acceptă conexiuni pe termen nelimitat"""
        self.init()
        print("Serverul ruleaza...")
        # se incarca cheia publica si privata
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

    def accept(self, sock):
        """Funcție de apel invers pentru când serverul este pregătit să accepte o conexiune."""
        client, _ = sock.accept()
        print("Inregistrare client...")
        client.send(self.pubKey.save_pkcs1(format="DER"))
        client.send("KEY".encode("ascii"))
        stringkey = client.recv(buffer_size)
        self.clientkey = rsa.PublicKey.load_pkcs1(stringkey, format="DER")
        client.send("HASH".encode("ascii"))
        hash_clientkey = hashlib.sha256(stringkey).hexdigest()
        hashkey = client.recv(buffer_size).decode()
        message = "f9dFd!LVC76zmh"
        with open("C:/Users/antonia/Desktop/Project/signature", "rb") as f:
            signature = f.read()
        os.remove("C:/Users/antonia/Desktop/Project/signature")
        try:
            if hashkey == hash_clientkey and rsa.verify(
                message.encode(), signature, self.clientkey
            ):
                print("Verificare reusita")
                clients[client] = self.clientkey
                self.read_selector.register(client, selectors.EVENT_READ, self.receive)
                self.write_selector.register(client, selectors.EVENT_WRITE)
        except rsa.VerificationError:
            print("Verificare nereusita")
            client.close()

    def receive(self, sock):
        """Functie de apel invers pentru atunci cand un socket client este gata sa primeasca."""
        try:
            msg = rsa.decrypt(sock.recv(buffer_size), self.privKey).decode("ascii")
            if msg.split(":", 1)[1] != "quit":
                for key, _ in self.write_selector.select(0):
                    if key.fileobj is not sock:
                        key.fileobj.send(
                            rsa.encrypt(msg.encode("ascii"), clients[key.fileobj])
                        )
        except (ConnectionResetError, rsa.DecryptionError):
            print("Clientul s-a deconectat")
            self.read_selector.unregister(sock)
            self.write_selector.unregister(sock)
            del clients[sock]
            sock.close()




if __name__ == "__main__":
    cs = ChatServer("localhost", 7342)
    cs.run()
