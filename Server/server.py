import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'mypassword',
            backend=default_backend()
        )

with open("public_key.pem", "rb") as key_file:
        public_key = load_pem_public_key(key_file.read(), backend=default_backend())

# Serializa a chave pública para enviar ao cliente
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Cria um socket de servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)

print('Aguardando conexão do cliente...')
conn, addr = server_socket.accept()
print('Conectado por', addr)

# Envia a chave pública para o cliente
conn.send(public_pem)

# Recebe e decifra a mensagem do cliente
encrypted_message = conn.recv(1024)
decrypted_message = private_key.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print('Mensagem recebida:', decrypted_message.decode('utf-8'))
conn.close()
