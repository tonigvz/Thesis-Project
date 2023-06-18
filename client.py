import threading, selectors, socket, rsa, random, os, glob, hashlib,customtkinter
from colorama import Fore

buffer_size = 2048
username = ""

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
        message = "f9dFd!LVC76zmh"
        signature = rsa.sign(message.encode(), self.privkey, "SHA-256")
        self.hash_key = hashlib.sha256(self.pubkey.save_pkcs1(format="DER")).hexdigest()
        with open("signature", "wb") as f:
            f.write(signature)
        for filename in glob.glob(
            f"C:/Users/antonia/Desktop/Project/client_keys/*.pem"
        ):
            os.remove(filename)

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.stringkey = self.socket.recv(buffer_size)
        self.serverkey = rsa.PublicKey.load_pkcs1(self.stringkey, format="DER")
        app2 = customtkinter.CTkToplevel()
        app2.focus_set()
        app2.grab_set()
        var = customtkinter.StringVar()
        label = customtkinter.CTkLabel(app2, textvariable=var)
        var.set("connection succesful" + "\n")
        k = self.socket.recv(buffer_size).decode("ascii")
        if k == "KEY":
            self.socket.send(self.pubkey.save_pkcs1(format="DER"))
            var.set(var.get() + "public key was sent" + "\n")
        h = self.socket.recv(buffer_size).decode("ascii")
        if h == "HASH":
            self.socket.send(self.hash_key.encode())
            var.set(var.get() +"public key verification succesful" + "\n")
        c = self.socket.recv(buffer_size).decode("ascii")
        var.set(var.get() + "all verifications passed,connection is secure")
        label.pack(padx=20,pady=20)
        self.threadrecv.start()

    def input(self):
        msg = app.entry.get()
        final = username + ":" + msg
        app.text.insert(customtkinter.END,msg+"\n")
        app.entry.delete(0,customtkinter.END)
        try:
            self.socket.send((rsa.encrypt(final.encode("ascii"), self.serverkey)))
            if msg == "quit":
                self.socket.close()
                app.quit()       
        except Exception as e:
            print(e)
        
        

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
                app.text.insert(customtkinter.END,msg+"\n")
            except ConnectionAbortedError:
                print("you closed the connection!")
                self.socket.close()
                break
            # except socket.error:
            #     print("server was closed")
            #     self.socket.close()
            #     break
            except rsa.DecryptionError:
                print("verification failed")
                self.socket.close()
                break
            except Exception as e:
                print(e)
                self.socket.close()
                break

class ToplevelWindow(customtkinter.CTkToplevel):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("200x200")
        self.title("Username")
        self.username = ""
        self.label = customtkinter.CTkLabel(self, text="enter your name sir")
        self.label.pack(padx=20, pady=20)
        self.user = customtkinter.CTkEntry(self)
        self.user.pack(padx=20, pady=20)
        self.button = customtkinter.CTkButton(self, text="send",command=self.user_input)
        self.button.pack(padx=20, pady=20)
    
    def user_input(self):
        self.username = self.user.get() 
        self.destroy()

class App(customtkinter.CTk,ChatClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("350x500")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure((0, 1), weight=1)
        self.text = customtkinter.CTkTextbox(self)
        self.text.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 0), sticky="nsew")
        self.entry = customtkinter.CTkEntry(self)
        self.entry.grid(row=1, column=0, padx=20, pady=20, sticky="ew")
        self.button = customtkinter.CTkButton(self,text="Send",command=client.input)
        self.button.grid(row=1, column=1, padx=20, pady=20, sticky="ew")
        self.toplevel_window = ToplevelWindow(self)
        self.toplevel_window.focus_set() # create window if its None or destroyed
        self.toplevel_window.grab_set()
        self.toplevel_window.protocol('WM_DELETE_WINDOW', self.doSomething)
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
