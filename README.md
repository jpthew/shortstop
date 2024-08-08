# Shortstop
![](./catchit.gif)

This project provides a secure way to exfiltrate data using RSA encryption. 

[![GPLv3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python3.8](https://github.com/jpthew/shortstop/actions/workflows/pylint.yml/badge.svg?branch=main&event=push&matrix.python-version=3.8)]
[![Python3.9](https://github.com/jpthew/shortstop/actions/workflows/pylint.yml/badge.svg?branch=main&event=push&matrix.python-version=3.9)]
[![Python3.10](https://github.com/jpthew/shortstop/actions/workflows/pylint.yml/badge.svg?branch=main&event=push&matrix.python-version=3.10)]
[![Python3.11](https://github.com/jpthew/shortstop/actions/workflows/pylint.yml/badge.svg?branch=main&event=push&matrix.python-version=3.11)]
[![Python3.12](https://github.com/jpthew/shortstop/actions/workflows/pylint.yml/badge.svg?branch=main&event=push&matrix.python-version=3.12)]

## Prerequisites
- Python 3
- Flask
- cryptography library
- gunicorn
- venv

Install the required Python packages using pip:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
A virtual environment is highly required for this project. All further python commands are run assuming that the user is in a venv.

## Server
The `server.py` module is the main server application. It provides endpoints to receive encrypted data and decrypt it.

## Key Management
The server uses RSA key pairs for encryption and decryption. The keys are managed using the following functions:

- `load_key_pair()`: Loads the RSA key pair from a file.
- `generate_key_pair()`: Generates a new RSA key pair.
- `save_key_pair(private_key, public_key)`: Saves the RSA key pair to a file.

## Endpoints
- `/api/v1/post`: Accepts POST requests with encrypted data. Only allows requests with a specific User-Agent and returns a 404 status for GET requests.
- `/api/v1/public_key`: Provides the public key for encryption.

## Example Usage
To run the server using gunicorn:
```bash
gunicorn -w 4 server:app
```
This spawns 4 different workers to handle web traffic. Use more/less depending on availability concerns.

## Client
The client.py module is a proof of concept for how to communicate with the server. It demonstrates how to encrypt data using the server's public key and send it to the server.

### Example Usage
To run the client:
```bash
python3 client.py
```
This will communicate to the server and send an encrypted "testing1234" message. Check the /tmp/log_xxxxxxx.txt to see these messages.
Modify the last line to validate that this message is changed. 

## Production Deployment
Deploy with nginx as a reverse proxy for multiple gunicorn instances hosted on a single machine. A sample `nginx.conf` is located in the `./nginx` directory.

## Security Considerations
- Deploy with TLS on production-ready servers. The current configuration is POC only, but allows for operational security if deployed against TLS inspected traffic.
- Ensure that the server is properly secured and only accessible to authorized clients.
- Use strong RSA key pairs and handle them securely. Additionally, increasing RSA keysize from 2048 may be warranted.
- ~~Regularly rotate the keys and update the clients accordingly~~. This is done automagically, and can be reconfigured. Default: 180s rotation. Keys are overwritten on each rotation.

## TODO
- Need to add receipt validation from `client.py` in case requests are sent *on* the key-cycle.

## License
This project is licensed under the GPLv3 License. See the LICENSE file for details.