from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os

class CryptorManager:
    def __init__(self, key):
        self.key = key
        
    def encryptor(self, data:dict) -> bytes:
        data = str(data).encode()
        iv = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            default_backend()
        ).encryptor()
        
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipherdata = encryptor.update(padded_data) + encryptor.finalize()
        return iv + cipherdata
    
    def decryptor(self, cipherdata: bytes) -> dict:
        iv = cipherdata[:16]
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            default_backend()
        ).decryptor()
        padded_data = decryptor.update(cipherdata[16:]) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return eval(data.decode())