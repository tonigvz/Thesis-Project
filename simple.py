import rsa
import os


(pubKey, privKey) = rsa.newkeys(1024)
with open("C:/Users/antonia/Desktop/Project/server_keys/pubKey.pem", "wb+") as f:
    f.write(pubKey.save_pkcs1("PEM"))
with open("C:/Users/antonia/Desktop/Project/server_keys/privKey.pem", "wb+") as f:
    f.write(privKey.save_pkcs1("PEM"))
(cpubKey, cprivKey) = rsa.newkeys(1024)
with open("C:/Users/antonia/Desktop/Project/client_keys/pubKey.pem", "wb+") as f:
    f.write(cpubKey.save_pkcs1("PEM"))
with open("C:/Users/antonia/Desktop/Project/client_keys/privKey.pem", "wb+") as f:
    f.write(cprivKey.save_pkcs1("PEM"))
