from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import os
import sys
import json
import json

def read_keys():
    public_key, private_key = None, None
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open("private_key.pem", "rb") as f:
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

    if not os.path.exists("private_key.pem"):
        with open("private_key.pem", "wb") as f:
            f.write(pem_private_key)

    if not os.path.exists("public_key.pem"):
        with open("public_key.pem", "wb") as f:
            f.write(pem_public_key)

    print("RSA keys generated and saved.")
    
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

def save_encryption_config(aes):
    config = {
        'aes': aes.hex()
    }
    with open('encryption_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    print("Encryption configuration saved.")

def load_aes_key():
    try:
        with open('encryption_config.json', 'r') as f:
            config = json.load(f)
            return bytes.fromhex(config['aes'])
    except FileNotFoundError:
        print("Error: encryption_config.json not found. Please encrypt data first.")
        sys.exit(1)
    except (KeyError, ValueError) as e:
        print(f"Error reading configuration: {str(e)}")
        sys.exit(1)