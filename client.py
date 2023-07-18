import  socket, rsa, customtkinter
from threading import Thread
from secrets import randbelow,choice
from os import remove
from glob import glob
from hashlib import sha256

buffer_size = 2048
username = ""

class ChatClient:
    def __init__(self, host, port): 
        self.host = host
        self.port = port
        self.pubkey, self.privkey = None, None
        self.serverkey = None
        self.threadrecv = Thread(target=self.recieve)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def generate(self):
        number_start = randbelow(1000)
        number_count = randbelow(20)
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
        choicek = choice(numbers)
        with open(
            f"C:/Users/antonia/Desktop/Project/client_keys/pubKey{choicek}.pem", "rb"
        ) as f:
            self.pubkey = rsa.PublicKey.load_pkcs1(f.read())
        with open(
            f"C:/Users/antonia/Desktop/Project/client_keys/privKey{choicek}.pem", "rb"
        ) as f:
            self.privkey = rsa.PrivateKey.load_pkcs1(f.read())
        message = "f9dFd!LVC76zmh"
        signature = rsa.sign(message.encode(), self.privkey, "SHA-256")
        self.hash_key = sha256(self.pubkey.save_pkcs1(format="DER")).hexdigest()
        with open("signature", "wb") as f:
            f.write(signature)
        for filename in glob(
            f"C:/Users/antonia/Desktop/Project/client_keys/*.pem"
        ):
            remove(filename)
        
    def connect(self):
        self.socket.connect((self.host, self.port))
        self.stringkey = self.socket.recv(buffer_size)
        self.serverkey = rsa.PublicKey.load_pkcs1(self.stringkey, format="DER")
        connect = customtkinter.CTkToplevel()
        connect.focus_set()
        connect.grab_set()
        var = customtkinter.StringVar()
        label = customtkinter.CTkLabel(connect, textvariable=var)
        label.pack(padx=20,pady=20)
        var.set("conexiune stabilita" + "\n")
        k = self.socket.recv(buffer_size).decode("ascii")
        if k == "KEY":
            self.socket.send(self.pubkey.save_pkcs1(format="DER")+self.hash_key.encode())
            var.set(var.get() + "cheie publica trimisa" + "\n")
            var.set(var.get() +"verificarea cheii publice a fost reusita" + "\n")
        
        var.set(var.get() + "toate verificarile au avut succes")
        self.threadrecv.start()

   

    def input(self):
        msg = app.entry.get()
        final = username + ":" + msg
        app.text.insert(customtkinter.END, msg + "\n")
        app.entry.delete(0, customtkinter.END)
        try:
            self.socket.send((rsa.encrypt(final.encode("ascii"), self.serverkey)))
            if msg == "quit":
                self.socket.close()
                app.quit()
        except Exception as e:
            app.text.insert(customtkinter.END, e)

    def recieve(self):
        while True:
            try:
                msg = rsa.decrypt(self.socket.recv(buffer_size), self.privkey).decode(
                    "ascii"
                )
                if msg == "regenerate":
                    self.generate()
                    self.socket.send("ready".encode("ascii"))
                    self.stringkey = self.socket.recv(buffer_size)
                    self.serverkey = rsa.PublicKey.load_pkcs1(self.stringkey, format="DER")
                    k = self.socket.recv(buffer_size).decode("ascii")
                    if k == "KEY2":
                        self.socket.send(self.pubkey.save_pkcs1(format="DER")+self.hash_key.encode())
                        app.text.insert(customtkinter.END, "cheile au fost schimbate" + "\n")
                else:
                    app.text.insert(customtkinter.END, msg + "\n")
            except ConnectionAbortedError:
                self.socket.close()
                break
            except Exception as e:
                print(e)
                break
            


class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("200x200")
        self.title("nume utilizator")
        self.username = ""
        self.label = customtkinter.CTkLabel(self, text="introduce numele dorit")
        self.label.pack(padx=20, pady=20)
        self.user = customtkinter.CTkEntry(self)
        self.user.pack(padx=20, pady=20)
        self.button = customtkinter.CTkButton(
            self, text="send", command=self.user_input
        )
        self.button.pack(padx=20, pady=20)

    def user_input(self):
        if self.user.get():
            self.username = self.user.get()
            self.destroy()
        else:
            pass
        
        
class App(customtkinter.CTk, ChatClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("350x500")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure((0, 1), weight=1)
        self.text = customtkinter.CTkTextbox(self)
        self.text.grid(
            row=0, column=0, columnspan=2, padx=20, pady=(20, 0), sticky="nsew"
        )
        self.entry = customtkinter.CTkEntry(self)
        self.entry.grid(row=1, column=0, padx=20, pady=20, sticky="ew")
        self.button = customtkinter.CTkButton(self, text="Send", command=client.input)
        self.button.grid(row=1, column=1, padx=20, pady=20, sticky="ew")
        self.toplevel_window = ToplevelWindow(self)
        self.toplevel_window.focus_set()
        self.toplevel_window.grab_set()
        self.toplevel_window.protocol("WM_DELETE_WINDOW", self.doSomething)
        self.toplevel_window.wait_window()
        self.user = self.toplevel_window.username

    def doSomething(self):
        if not self.toplevel_window.username:
            pass


if __name__ == "__main__":
    client = ChatClient("localhost", 7342)
    app = App()
    username = app.user
    client.generate()
    client.connect()
    app.mainloop()
    client.socket.close()
