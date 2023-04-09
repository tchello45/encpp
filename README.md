# encpp - Encryption Plus Plus 

Encryption Plus Plus is a python module to encrypt messages secure using AES-256 or a combination with RSA and AES-256.
It's very secure and easy to handle. For an AES key you can use strings!

# Installation
```sh
pip install encpp
```
# Usage

# AES:
```python
from encpp.encpp import *
enc = encpp.aes("password".encode()).encrypt("Hello World".encode())

dec = encpp.aes("password".encode()).decrypt(enc).decode()
```

# RSA:
```python
from encpp.encpp import *
import rsa

pub, priv = rsa.newkeys(2048)

enc = encpp.rsa.encrypt(pub, "Hello World".encode())

dec = encpp.rsa.decrypt(priv, enc).decode()
```
