import threading, selectors, socket, rsa, random, os, glob, hashlib
from colorama import Fore

buffer_size = 1024


class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.username = username
        self.pubkey, self.privkey = None, None
        self.serverkey = None
        self.threadsend = threading.Thread(target=self.input)
        self.threadrecv = threading.Thread(target=self.recieve)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.read_selector = selectors.DefaultSelector()

    def generate(self):
        number_start = random.randint(1, 1000)
        number_count = random.randint(1, 20)
        numbers = []
        while len(numbers) < number_count:
            numbers.append(number_start)
            number_start += 1
        (cpubKey, cprivKey) = rsa.newkeys(buffer_size)
        for i in numbers:
            with open(
                f"C:/Users/antonia/Desktop/Project/client_keys/pubKey{i}.pem", "wb+"
            ) as f:
                f.write(cpubKey.save_pkcs1("PEM"))
            with open(
                f"C:/Users/antonia/Desktop/Project/client_keys/privKey{i}.pem", "wb+"
            ) as f:
                f.write(cprivKey.save_pkcs1("PEM"))
        choice = random.choice(numbers)
        with open(
            f"C:/Users/antonia/Desktop/Project/client_keys/pubKey{choice}.pem", "rb"
        ) as f:
            self.pubkey = rsa.PublicKey.load_pkcs1(f.read())
        with open(
            f"C:/Users/antonia/Desktop/Project/client_keys/privKey{choice}.pem", "rb"
        ) as f:
            self.privkey = rsa.PrivateKey.load_pkcs1(f.read())
        for filename in glob.glob(
            f"C:/Users/antonia/Desktop/Project/client_keys/*.pem"
        ):
            os.remove(filename)

    def input(self):
        while True:
            msg = input()
            final = username + ":" + msg
            try:
                self.socket.send((rsa.encrypt(final.encode("ascii"), self.serverkey)))
                if msg == "quit":
                    self.socket.close()
                    break
            except:
                break

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.stringkey = self.socket.recv(buffer_size)
        self.serverkey = rsa.PublicKey.load_pkcs1(self.stringkey, format="DER")
        hash_key = hashlib.sha256(self.pubkey.save_pkcs1(format="DER")).hexdigest()
        s = self.socket.recv(buffer_size).decode("ascii")
        if s == "KEY":
            self.socket.send(self.pubkey.save_pkcs1(format="DER"))
        h = self.socket.recv(buffer_size).decode("ascii")
        if h == "HASH":
            self.socket.send(hash_key.encode())
        self.threadsend.start()
        self.threadrecv.start()

    def recieve(self):
        while True:
            try:
                msg = rsa.decrypt(self.socket.recv(buffer_size), self.privkey).decode(
                    "ascii"
                )
                print(
                    Fore.BLUE
                    + msg.split(":", 1)[0]
                    + ":"
                    + Fore.WHITE
                    + msg.split(":", 1)[1]
                    + Fore.RESET
                )
            except ConnectionAbortedError:
                print("you closed the connection!")
                self.socket.close()
                break
            except socket.error:
                print("server was closed")
                self.socket.close()
                break
            except:
                print("an error occured!")
                self.socket.close()
                break


if __name__ == "__main__":
    username = input("choose your username sir: ")
    client = ChatClient("localhost", 7342)
    client.generate()
    client.connect()
