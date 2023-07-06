import selectors, socket, rsa, threading, hashlib, os, random, glob,time


clients = {}
buffer_size = 2048


class ChatServer:
    def __init__(self, host, port):
        """Initializare atribute server."""
        self.host = host
        self.port = port
        self.username = None
        self.socket = None
        self.pubKey, self.privKey = None, None
        self.clientkey = None
        self.read_selector = selectors.DefaultSelector()
        self.write_selector = selectors.DefaultSelector()
        self.counter =  random.randint(60, 600)
        self.timer = threading.Timer(self.counter, self.regenerate)

    def generate(self):
        """Se genereaza cheile in mod random ,se incarca in variabile si se sterg"""
        number_start = random.randint(1, 1000)
        number_count = random.randint(1, 20)
        numbers = []
        while len(numbers) < number_count:
            numbers.append(number_start)
            number_start += 1
        (pubKey, privKey) = rsa.newkeys(buffer_size)
        for i in numbers:
            with open(
                f"C:/Users/antonia/Desktop/Project/server_keys/pubKey{i}.pem", "wb+"
            ) as f:
                f.write(pubKey.save_pkcs1("PEM"))
            with open(
                f"C:/Users/antonia/Desktop/Project/server_keys/privKey{i}.pem", "wb+"
            ) as f:
                f.write(privKey.save_pkcs1("PEM"))
        choice = random.choice(numbers)
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/pubKey{choice}.pem", "rb"
        ) as f:
            self.pubKey = rsa.PublicKey.load_pkcs1(f.read())
        with open(
            f"C:/Users/antonia/Desktop/Project/server_keys/privKey{choice}.pem", "rb"
        ) as f:
            self.privKey = rsa.PrivateKey.load_pkcs1(f.read())
        for filename in glob.glob(
            f"C:/Users/antonia/Desktop/Project/server_keys/*.pem"
        ):
            os.remove(filename)
        


    def init(self):
        """Initializeaza socket-ul serverului."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        """Se pune socket-ul in spatiul de depozitare al selectorului"""
        self.read_selector.register(
            self.socket,
            selectors.EVENT_READ,
            self.accept,
        )  


    def run(self):
        """Pornește serverul și acceptă conexiuni pe termen nelimitat"""
        self.init()
        print("Serverul ruleaza...")
        self.timer.start()
        print(self.counter)
        while True:
            for key, _ in self.read_selector.select():
                sock, callback = key.fileobj, key.data
                callback(sock)
        

    def accept(self, sock):
        """Funcție de apel invers pentru când serverul este pregătit să accepte o conexiune."""
        client, _ = sock.accept()
        print(self.counter)
        print("Inregistrare client...")
        client.send(self.pubKey.save_pkcs1(format="DER"))
        client.send("KEY".encode("ascii"))
        stringkey = client.recv(buffer_size)
        hashkey = stringkey[-64:].decode()
        self.clientkey = rsa.PublicKey.load_pkcs1(stringkey[:-64], format="DER")
        hash_clientkey = hashlib.sha256(stringkey[:-64]).hexdigest()
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

    def regenerate(self):
        if clients:
            self.generate()
            for key in clients:
                    key.send(rsa.encrypt("regenerate".encode("ascii"), clients[key]))
                    output = key.recv(buffer_size).decode()
                    if output == "ready":
                        key.send(self.pubKey.save_pkcs1(format="DER"))
                        key.send("KEY2".encode("ascii"))
                        stringkey = key.recv(buffer_size)
                        hashkey = stringkey[-64:].decode()
                        self.clientkey = rsa.PublicKey.load_pkcs1(stringkey[:-64], format="DER")
                        print("chei publice schimbate")
                        hash_clientkey = hashlib.sha256(stringkey[:-64]).hexdigest()
                        message = "f9dFd!LVC76zmh"
                        with open("C:/Users/antonia/Desktop/Project/signature", "rb") as f:
                            signature = f.read()
                        os.remove("C:/Users/antonia/Desktop/Project/signature")
                        print(signature)
                        print(hashkey,hash_clientkey)
                        if hashkey == hash_clientkey and rsa.verify(
                                message.encode(), signature, self.clientkey
                            ):
                            clients[key] = self.clientkey
                            self.counter =  random.randint(60, 600)
                        else:
                            print("Verificare nereusita")
                            key.close()

        
        
                

if __name__ == "__main__":
    cs = ChatServer("localhost", 7342)
    cs.generate()
    cs.run()
    
       
    
    
