import threading
import selectors
import socket
import rsa
import sys
from colorama import Fore

with open(f"C:/Users/antonia/Desktop/Project/client_keys/pubKey.pem", "rb") as f:
    pubkey = rsa.PublicKey.load_pkcs1(f.read())
with open("C:/Users/antonia/Desktop/Project/client_keys/privKey.pem", "rb") as f:
    privkey = rsa.PrivateKey.load_pkcs1(f.read())


class ChatClient:
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._username = username
        self._pubkey, self._privkey = pubkey, privkey
        self._th = threading.Thread(target=self._input_and_send_loop)
        self._serverkey = None
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._read_selector = selectors.DefaultSelector()

    def _input_and_send_loop(self):
        while True:
            msg = input()
            final = username + ":" + msg
            if msg == "quit":
                self._socket.send((rsa.encrypt(final.encode("ascii"), self._serverkey)))
                print("you exited the chat")
                break
            else:
                try:
                    self._socket.send(
                        (rsa.encrypt(final.encode("ascii"), self._serverkey))
                    )
                except:
                    break

    def connect(self):
        self._socket.connect((self._host, self._port))
        self._stringkey = self._socket.recv(1024)
        self._serverkey = rsa.PublicKey.load_pkcs1(self._stringkey, format="DER")
        self._th.start()
        self._th.join()
        while True:
            try:
                msg = rsa.decrypt(self._socket.recv(1024), self._privkey).decode(
                    "ascii"
                )
                print(
                    Fore.GREEN
                    + msg.split(":", 1)[0]
                    + ":"
                    + Fore.WHITE
                    + msg.split(":", 1)[1]
                )
            except (ConnectionResetError, ConnectionAbortedError):
                print("connection was lost")
                break
            except:
                print("connection closed")
                break
        sys.exit()


if __name__ == "__main__":
    username = input("choose your username sir: ")
    client = ChatClient("localhost", 7342)
    client.connect()
