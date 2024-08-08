"""
Crypto_utils module provides utility functions for cryptography operations.
"""
# crypto_utils.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def oaep_padding():
    """
    Create an OAEP padding object with SHA-256 as the hash algorithm.
    
    This function creates an OAEP padding object with SHA-256 as the hash algorithm
    
    Returns:
        cryptography.hazmat.primitives.asymmetric.padding.OAEP: The OAEP padding object.
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )