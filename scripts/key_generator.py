from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import os
import sys
import json

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(__file__))

KEYS_DIR = os.path.join(get_base_path(), '.keys')

def read_keys():
    public_key, private_key = None, None
    with open(os.path.join(KEYS_DIR, "public_key.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(os.path.join(KEYS_DIR, "private_key.pem"), "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        
    return public_key, private_key

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key_path = os.path.join(KEYS_DIR, "private_key.pem")
    public_key_path = os.path.join(KEYS_DIR, "public_key.pem")

    if not os.path.exists(private_key_path):
        with open(private_key_path, "wb") as f:
            f.write(pem_private_key)

    if not os.path.exists(public_key_path):
        with open(public_key_path, "wb") as f:
            f.write(pem_public_key)

    print("RSA keys generated and saved in the .keys directory.")
    
def generate_aes_key():
    return os.urandom(32)

def generate_iv():
    return os.urandom(16)

def generate_keys():
    generate_rsa_keypair()
    public_key, private_key = read_keys()
    aes_key = generate_aes_key()
    iv = generate_iv()
    
    return public_key, private_key, aes_key, iv

def save_aes(aes):
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(os.path.join(KEYS_DIR, 'aes.key'), 'wb') as fo:
        fo.write(aes)
        
    print(f"AES key saved to: {os.path.join(KEYS_DIR, 'aes.key')}")
    print("Encryption configuration saved in the keys directory.")

def load_aes_key():
    try:
        with open(os.path.join(KEYS_DIR, "aes.key"), 'rb') as fo:
            return fo.read()
    except FileNotFoundError:
        print("Error: aes.key not found in the keys directory. Please encrypt data first.")
        sys.exit(1)
    except (KeyError, ValueError) as e:
        print(f"Error reading configuration: {str(e)}")
        sys.exit(1)