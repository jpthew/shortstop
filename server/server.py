from flask import Flask, request, Response, abort
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import threading
import time
import datetime

app = Flask(__name__)

KEY_FILE = '/tmp/key_pair.pem'

def load_key_pair():
    with open(KEY_FILE, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
        public_key = private_key.public_key()
    return private_key, public_key

def generate_key_pair():
    key_size = 2048

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    public_key = private_key.public_key()
    return private_key, public_key

def save_key_pair(private_key, public_key):
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

def update_key_pair():
    while True:
        private_key, public_key = generate_key_pair()
        save_key_pair(private_key, public_key)
        time.sleep(180)

threading.Thread(target=update_key_pair, daemon=True).start()

def decrypt_data(encrypted_data):
    private_key, _ = load_key_pair()
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

@app.route('/api/v1/post', methods=['POST', 'GET'])
def decrypt_view():
    encrypted_data = request.data
    user_agent = request.headers.get('User-Agent')
    if user_agent != "SpecificUserAgent":
        abort(404)
    if request.method == 'GET':
        abort(404)
    try:
        decrypted_data = decrypt_data(encrypted_data)
        log_file = f"/tmp/log_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(log_file, 'a') as f:
            f.write(decrypted_data.decode())
        return Response(status=200)
    except Exception as e:
        return Response(status=404)

@app.route('/api/v1/public_key', methods=['GET'])
def get_public_key():
    user_agent = request.headers.get('User-Agent')
    if user_agent != "SpecificUserAgent":
        abort(404)    
    private_key, public_key = load_key_pair()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)