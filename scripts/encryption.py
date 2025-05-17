from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from scripts.key_generator import generate_aes_keys
import os

def encrypt_aes(public_key, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_aes_key, encryptor

def encrypt(data, public_key, aes_key, iv):
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    encrypted_aes_key, encryptor = encrypt_aes(public_key, aes_key, iv)
        
    pad_len = 16 - (len(data) % 16)
    padded_plaintext = data + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    print("File encrypted successfully.")
    return encrypted_aes_key, iv, ciphertext

def decrypt(encrypted_data, private_key, encrypted_aes_key, iv):
    decrypted_aes_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
    pad_len = decrypted_padded[-1]
    decrypted = decrypted_padded[:-pad_len]

    return decrypted