from scripts.key_generator import generate_keys, generate_aes_key, save_encryption_config, load_encryption_config
from scripts.encryption import encrypt, decrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse
import os
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description='Encrypt and decrypt data using RSA and AES')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True,
                       help='Mode of operation: encrypt or decrypt')
    parser.add_argument('--data', required=True,
                       help='Data to encrypt/decrypt')
    parser.add_argument('--generate-keys', action='store_true',
                       help='Generate new key pairs')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    try:
        if args.generate_keys:
            public_key, private_key, aes_key, iv = generate_keys()
            print("New keys generated successfully")
        else:
            try:
                # Try to read existing keys
                with open("public_key.pem", "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
                with open("private_key.pem", "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)
                print("Using existing RSA keys")
            except FileNotFoundError:
                # If keys don't exist, generate new ones
                public_key, private_key, _, _ = generate_keys()
                print("No existing keys found. Generated new RSA keys")
                
        # Always generate new AES key and IV for each encryption
        # For encryption mode, try to load existing config or generate new keys
        if args.mode == 'encrypt':
            if args.generate_keys or not os.path.exists('encryption_config.json'):
                aes_key = os.urandom(32)  # 256-bit key
                iv = os.urandom(16)  # 128-bit IV
                print("Generating new AES key and IV")
            else:
                # Use existing encryption configuration
                try:
                    encrypted_aes_existing, iv = load_encryption_config()
                    # We need to decrypt the existing AES key
                    aes_key = private_key.decrypt(
                        encrypted_aes_existing,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print("Using existing AES key and IV")
                except Exception as e:
                    print(f"Error loading existing encryption config: {str(e)}")
                    sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
        
    if args.mode == 'encrypt':
        encrypted_aes, iv, ciphertext = encrypt(args.data, public_key, aes_key, iv)
        if args.generate_keys or not os.path.exists('encryption_config.json'):
            save_encryption_config(encrypted_aes, iv)
            print("Encryption configuration saved to encryption_config.json")
        print(f"Encrypted data: {ciphertext.hex()}")
    else:
        try:
            ciphertext = bytes.fromhex(args.data)
            encrypted_aes, iv = load_encryption_config()
            decrypted_data = decrypt(ciphertext, private_key, encrypted_aes, iv)
            print(f"Decrypted data: {decrypted_data}")
        except ValueError as e:
            print(f"Error: Invalid hex value provided - {str(e)}")
            sys.exit(1)