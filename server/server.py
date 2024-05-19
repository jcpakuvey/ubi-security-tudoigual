import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'util')))
from watchdog_handler import WatchdogHandler
from security_util import generate_keys

class SecureServer:
    def __init__(self, host, port, private_key_file, public_key_file, password):
        generate_keys(private_key_file, public_key_file, password)

        self.host = host
        self.port = port
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
        print('server')

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        print('Aguardando conexão do cliente...')
        conn, addr = server_socket.accept()
        print('Conectado por', addr)

        # Envia a chave pública para o cliente
        conn.send(self.public_pem)

        # Recebe e decifra a mensagem do cliente
        encrypted_message = conn.recv(1024)
        decrypted_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print('Mensagem recebida:', decrypted_message.decode('utf-8'))
        conn.close()
