import rsa
import random
import os, glob

number_start = random.randint(1, 1000)
number_count = random.randint(1, 20)
print(number_start, number_count)
numbers = []
while len(numbers) < number_count:
    numbers.append(number_start)
    number_start += 1
print(numbers, random.choice(numbers))
for filename in glob.glob(f"C:/Users/antonia/Desktop/Project/server_keys/*.pem"):
    os.remove(filename)
for filename in glob.glob(f"C:/Users/antonia/Desktop/Project/client_keys/*.pem"):
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
for i in numbers:
    (cpubKey, cprivKey) = rsa.newkeys(1024)
    with open(
        f"C:/Users/antonia/Desktop/Project/client_keys/pubKey{i}.pem", "wb+"
    ) as f:
        f.write(cpubKey.save_pkcs1("PEM"))
    with open(
        f"C:/Users/antonia/Desktop/Project/client_keys/privKey{i}.pem", "wb+"
    ) as f:
        f.write(cprivKey.save_pkcs1("PEM"))
