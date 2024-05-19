import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'util')))
from security_util import generate_keys

class Client:
    def __init__(self, server_host, server_port, private_key_file, public_key_file, password):
        generate_keys(private_key_file, public_key_file, password)

        self.server_host = server_host
        self.server_port = server_port
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self.password = password.encode('utf-8')
        self.private_key = self.load_private_key()
        self.public_key = self.load_public_key()
        self.public_pem = self.serialize_public_key()



    def load_private_key(self):
        with open(self.private_key_file, "rb") as key_file:
            return load_pem_private_key(
                key_file.read(),
                password=self.password,
                backend=default_backend()
            )

    def load_public_key(self):
        with open(self.public_key_file, "rb") as key_file:
            return load_pem_public_key(key_file.read(), backend=default_backend())

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def handle_new_file(self, path):
        print(path)
        print('client')

    def send_file(self, filename):
        encrypted_filename = self.encrypt_file(filename)

        # Send the encrypted file to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server_host, self.server_port))
            with open(encrypted_filename, "rb") as f:
                data = f.read()
                s.sendall(data)

        print(f"Arquivo {encrypted_filename} enviado para o servidor.")

# Exemplo de uso
#if __name__ == "__main__":
#    client = Client(server_host='localhost', server_port=65432, public_key_file='public_key.pem')
#    client.send_file('example.txt')
