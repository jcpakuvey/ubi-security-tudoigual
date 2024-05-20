import socket
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'util')))
from security_util import generate_keys

class Client:
    def __init__(self, server_host, server_port, private_key_file, public_key_file, password, watch_path):
        generate_keys(private_key_file, public_key_file, password)

        self.server_host = server_host
        self.server_port = server_port
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self.password = password.encode('utf-8')
        self.private_key = self.load_private_key()
        self.public_key = self.load_public_key()
        self.public_pem = self.serialize_public_key()
        self.watch_path = watch_path


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

    def handle_new_file(self, path, encrypted_key):
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.send_file(s, path)

            self.send_key(s, encrypted_key)
        #self.send_login_request('teste','teste')
        

    def send_file(self,s, filename):
        file_name = os.path.basename(filename)
        file_name_encoded = file_name.encode('utf-8')
        file_name_length = len(file_name_encoded)

        s.connect((self.server_host, self.server_port))
        s.sendall(b"FILE")
        s.sendall(struct.pack('!I', file_name_length))  # Envia o tamanho do nome do arquivo
        s.sendall(file_name_encoded)  # Envia o nome do arquivo
        with open(filename, "rb") as f:
            while (data := f.read(1024)):
                s.sendall(data)  # Envia o conteúdo do arquivo
        print(f"Arquivo {filename} enviado para o servidor.")

    def send_key(self,s,  key):
        s.sendall(b"KEY")
        s.sendall(key)
        print("Chave enviada para o servidor.")

    def send_login_request(self, username, password):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server_host, self.server_port))
            s.sendall(b"LOGIN")
            s.sendall(username.encode('utf-8') + b'\n' + password.encode('utf-8'))
            print("Pedido de login enviado para o servidor.")
