import threading, selectors, socket, rsa, sys, random, os, glob, time
from colorama import Fore

number_start = random.randint(1, 1000)
number_count = random.randint(1, 20)
numbers = []
while len(numbers) < number_count:
    numbers.append(number_start)
    number_start += 1
(cpubKey, cprivKey) = rsa.newkeys(1024)
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
    pubKey = rsa.PublicKey.load_pkcs1(f.read())
with open(
    f"C:/Users/antonia/Desktop/Project/client_keys/privKey{choice}.pem", "rb"
) as f:
    privKey = rsa.PrivateKey.load_pkcs1(f.read())
for filename in glob.glob(f"C:/Users/antonia/Desktop/Project/client_keys/*.pem"):
    os.remove(filename)


class ChatClient:
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._username = username
        self._pubkey, self._privkey = pubKey, privKey
        self._serverkey = None
        self._threadsend = threading.Thread(target=self.input)
        self._threadrecv = threading.Thread(target=self.recieve)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._read_selector = selectors.DefaultSelector()

    def input(self):
        while True:
            msg = input()
            final = username + ":" + msg
            try:
                self._socket.send((rsa.encrypt(final.encode("ascii"), self._serverkey)))
            except:
                break

    def connect(self):
        self._socket.connect((self._host, self._port))
        self._stringkey = self._socket.recv(1024)
        self._serverkey = rsa.PublicKey.load_pkcs1(self._stringkey, format="DER")
        s = self._socket.recv(1024).decode("ascii")
        if s == "KEY":
            self._socket.send(self._pubkey.save_pkcs1(format="DER"))
        self._threadsend.start()
        self._threadrecv.start()

    def recieve(self):
        while True:
            try:
                msg = rsa.decrypt(self._socket.recv(1024), self._privkey).decode(
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
            except:
                print("an error occured!")
                self._socket.close()
                break


if __name__ == "__main__":
    username = input("choose your username sir: ")
    client = ChatClient("localhost", 7342)
    client.connect()
    sys.exit(1)
