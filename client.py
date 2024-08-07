import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def get_rsa_pub_key():
    url = "http://localhost:8000/api/v1/public_key"
    response = requests.get(url)
    return response.content

def encrypt_data(data):
    public_key = serialization.load_pem_public_key(
        get_rsa_pub_key()
    )
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def sendit(raw):
    url = "http://localhost:8000/api/v1/post"
    data = encrypt_data(raw)
    headers = {
        'User-Agent': 'SpecificUserAgent'
    }
    response = requests.post(url=url, data=data, headers=headers)
    return response

print(sendit(b"testing1234"))