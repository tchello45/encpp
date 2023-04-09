#------------------------------#
# encpp                        #
# Encryption PLus Plus         #
# Author: Tilman Kurmayer      #
# Version: 1.0.0               #	
# License: MIT                 #
#------------------------------#
import os 
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
class encpp:
    class aes:
        def __init__(self, key:bytes) -> None:
            # Generate a key from the given password
            self.key = hashlib.pbkdf2_hmac('sha3_256', key, b'', 100000)
        def encrypt(self, data:bytes)-> bytes:
            # Generate an initialisation vector
            iv = os.urandom(AES.block_size)
            # Derive an encryption key from the given key
            enc_key = hashlib.pbkdf2_hmac('sha3_256', self.key, iv, 100000)
            # Create a cipher using the derived key
            cipher = AES.new(enc_key, AES.MODE_CBC, iv)
            # Pad the data for encryption
            data_padded = pad(data, AES.block_size)
            # Encrypt the data
            ct_bytes = cipher.encrypt(data_padded)
            # Return the initialisation vector and encrypted data
            return iv + ct_bytes
        def decrypt(self, data:bytes)-> bytes:
            # Extract the initialisation vector from the data
            iv = data[:AES.block_size]
            # Derive a decryption key from the given key
            dec_key = hashlib.pbkdf2_hmac('sha3_256', self.key, iv, 100000)
            # Create a cipher using the derived key
            cipher = AES.new(dec_key, AES.MODE_CBC, iv)
            # Decrypt the data
            pt = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
            # Return the decrypted data
            return pt
    class rsa:
        @staticmethod
        def encrypt(public_key:rsa.PublicKey, data:bytes) -> bytes:
            # Generate a random key
            aes_key = os.urandom(32)
            # Encrypt the data with AES
            enc = encpp.aes(aes_key).encrypt(data)
            # Encrypt the AES key with RSA
            rsa_enc = rsa.encrypt(aes_key, public_key)
            # Return the encrypted RSA key and encrypted data
            return rsa_enc + "sep".encode() + enc
        @staticmethod
        def decrypt(private_key:rsa.PrivateKey, data:bytes) -> bytes:
            # Extract the encrypted RSA key from the data
            aes_key, enc = data.split("sep".encode())
            # Decrypt the AES key with RSA
            aes_key = rsa.decrypt(aes_key, private_key)
            # Decrypt the data with AES
            return encpp.aes(aes_key).decrypt(enc)
