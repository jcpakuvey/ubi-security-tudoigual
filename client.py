import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Cria um socket de cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

# Recebe a chave pública do servidor
public_pem = client_socket.recv(1024)
public_key = serialization.load_pem_public_key(public_pem)

# Mensagem a ser enviada
message = "Olá, servidor!"
encrypted_message = public_key.encrypt(
    message.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Envia a mensagem cifrada para o servidor
client_socket.send(encrypted_message)
client_socket.close()
