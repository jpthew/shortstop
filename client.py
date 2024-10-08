"""
client.py

This module provides functionality to encrypt data using RSA public key
encryption and send it to a specified URL via an HTTP POST request.

Functions:
- get_rsa_pub_key(): Retrieves the RSA public key.
- encrypt_data(data): Encrypts the provided data using the RSA public key.
- sendit(raw): Encrypts the raw data and sends it to the specified URL.

Usage:
    Run this module directly to test the sendit function with sample data.
"""

import sys
import requests
from cryptography.hazmat.primitives import serialization
from modules.crypto_utils import oaep_padding

def get_rsa_pub_key(url: str="http://localhost:8000/api/v1/public_key", timeout: int=5):
    """
    Retrieves the RSA public key from the specified URL.

    This function sends an HTTP GET request to the specified URL to retrieve the
    RSA public key. If except, it will exit the program. Ensure useragent is set.

    Args:
        url (str): The URL to send the HTTP GET request to.
        timeout (int): The timeout in seconds for the HTTP GET request.

    Returns:
        bytes: The RSA public key in PEM format.

    Raises:
        requests.exceptions.RequestException: An error occurred while sending the HTTP GET request.

    """
    try:
        headers = {
            'User-Agent': 'SpecificUserAgent'
        }
        response = requests.get(url, timeout=timeout, headers=headers)
        return response.content
    except requests.exceptions.ConnectionError:
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        raise e

def encrypt_data(data):
    """
    Encrypts the provided data using the RSA public key.

    This function encrypts the provided data using the RSA public key with OAEP
    padding and SHA-256 hashing.

    Args:
        data (bytes): The data to encrypt.

    Returns:
        bytes: The encrypted data.

    Raises:
        ValueError: An error occurred while encrypting the data
    """
    try:
        public_key = serialization.load_pem_public_key(
            get_rsa_pub_key()
        )
    except ValueError:
        sys.exit(1)
    try:
        encrypted_data = public_key.encrypt(
            data,
            oaep_padding()
        )
    except ValueError as e:
        raise e
    return encrypted_data

def sendit(raw):
    """
    Delivers the encrypted data to the specified URL.

    This function encrypts the provided data using the RSA public key and sends
    it to the specified URL via an HTTP POST request.

    Args:
        raw (bytes): The data to send.

    Returns:
        requests.models.Response: The response from the HTTP POST request.

    Raises:
        requests.exceptions.RequestException: An error occurred while sending the HTTP POST request.

    """
    url = "http://localhost:8000/api/v1/post"
    data = encrypt_data(raw)
    headers = {
        'User-Agent': 'SpecificUserAgent'
    }
    try:
        response = requests.post(url=url, data=data, headers=headers, timeout=5)
    except requests.exceptions.RequestException as e:
        raise e
    return response

if __name__ == "__main__":
    sendit(b"testing1234")
    # print(sendit(b"testing1234")) # Uncomment this line to print the response content
