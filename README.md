# Encryptor

A Python-based encryption tool that implements hybrid RSA/AES encryption for secure data handling. This tool uses RSA for key exchange and AES for efficient data encryption.

## Features

- Hybrid encryption system using RSA (4096-bit) and AES (256-bit)
- Command-line interface for easy usage
- Support for both encryption and decryption operations
- Secure key generation and management
- Configuration persistence for encryption settings

## Prerequisites

- Python 3.x
- Virtual environment (recommended)

## Installation

1. Clone the repository

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
.\venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install cryptography pyinstaller
```

## Usage

The tool can be run using the provided `run` script or directly with Python.

### Basic Commands

1. Generate new keys and encrypt data:
```bash
python encryptor.py --mode encrypt --data "Your secret message" --generate-keys
```

2. Encrypt data using existing keys:
```bash
python encryptor.py --mode encrypt --data "Your secret message"
```

3. Decrypt data:
```bash
python encryptor.py --mode decrypt --data "<encrypted-hex-string>"
```

### Using the Run Script

Make the run script executable and use it to create a standalone executable:
```bash
chmod +x ./run
./run
```

This will create a standalone executable in the `dist` directory.

## Security Notes

- Keep your private key secure and never share it
- The `.gitignore` is configured to prevent accidentally committing key files (*.pem)
- A new AES key is generated for each encryption operation
- The encrypted AES key and IV are stored in `encryption_config.json`

## Project Structure

- `encryptor.py`: Main application entry point and CLI interface
- `scripts/encryption.py`: Core encryption/decryption functions
- `scripts/key_generator.py`: Key generation and management

## Warning

Never store sensitive private keys in the repository. The `.gitignore` file is configured to prevent this, but exercise caution when handling key files.

## Dependencies

- cryptography: For encryption operations
- pyinstaller: For creating standalone executables
