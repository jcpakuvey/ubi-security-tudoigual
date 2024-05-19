from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_keys(private_key_file, public_key_file, password):
    # Check if the keys already exist
    if os.path.isfile(private_key_file) and os.path.isfile(public_key_file):
        return

    # Generate private/public key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save the private key to a file
    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        ))

    # Save the public key to a file
    with open(public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def encrypt_file(filename, public_key_file):
    # Load the public key
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    # Generate a symmetric key
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the file
    with open(filename, "rb") as f:
        file_data = f.read()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # Encrypt the symmetric key with the public key
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted file
    with open(filename + ".enc", "wb") as f:
        f.write(encrypted_key)
        f.write(iv)
        f.write(encrypted_data)

def decrypt_file(encrypted_filename, private_key_file, password):
    # Check if the files exist
    if not os.path.isfile(encrypted_filename) or not os.path.isfile(private_key_file):
        print('Erro: Arquivo não encontrado.')
        return

    # Load the private key
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode('utf-8'),
            backend=default_backend()
        )

    # Read the encrypted file
    with open(encrypted_filename, "rb") as f:
        encrypted_key = f.read(256)
        iv = f.read(16)
        ciphertext = f.read()

    # Decrypt the symmetric key with the private key
    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Save the decrypted file
    decrypted_filename = encrypted_filename.replace(".enc", ".dec")
    with open(decrypted_filename, "wb") as f:
        f.write(plaintext)

    print(f'Arquivo descriptografado salvo como {decrypted_filename}')


def sign_file(filename, private_key_file, password):
    # Load the private key
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )

    # Read the file to be signed
    with open(filename, "rb") as f:
        file_data = f.read()

    # Sign the file
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save the signature to a file
    signature_filename = filename + ".sig"
    with open(signature_filename, "wb") as f:
        f.write(signature)

    print(f'Assinatura salva como {signature_filename}')
    return signature_filename

def verify_signature(filename, public_key_file, signature_file):
    # Load the public key
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    # Read the file and the signature
    with open(filename, "rb") as f:
        file_data = f.read()
    with open(signature_file, "rb") as f:
        signature = f.read()

    # Verify the signature
    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Assinatura verificada com sucesso!")
    except Exception as e:
        print(f"Falha na verificação da assinatura: {e}")
