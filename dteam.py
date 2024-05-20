import os
import click
import threading
import time
from watchdog.observers import Observer
from client.client import Client
from util.security_util import encrypt_file, generate_keys,decrypt_file, verify_signature, sign_file
from server.server import SecureServer
from util.watchdog_handler import WatchdogHandler

def start_watchdog(path,client=None, server=None):
    event_handler = WatchdogHandler(client, server)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print(f'Monitorando a pasta: {path}')

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


@click.group()
def dteam():
    """Um grupo de comandos para a aplicação TUDOIGUAL"""
    pass

@dteam.command(name="start-server")
@click.option('--host', default='localhost', help='Host do servidor')
@click.option('--port', default=65432, help='Porta do servidor')
@click.option('--private-key-file', default='private_server_key.pem', help='Caminho para o arquivo da chave privada')
@click.option('--public-key-file', default='public_server_key.pem', help='Caminho para o arquivo da chave pública')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Senha para a chave privada')
@click.option('--watch-path', default='./share-server', help='Pasta para monitorar com o Watchdog')
@click.option('--key-path', default='./k-server', help='Pasta para salvar as chaves')
def start_server(host, port, private_key_file, public_key_file, password, watch_path, key_path):

    """Inicia o servidor seguro para comunicação e o watchdog para monitorar a pasta especificada"""
    server = SecureServer(host, port, private_key_file, public_key_file, password, watch_path, key_path)

    # Start the server in a separate thread or process if needed
    server_thread = threading.Thread(target=server.start_server)
    server_thread.start()
    
    # Start the watchdog to monitor the specified path
    start_watchdog(watch_path, client=None, server=server)

@dteam.command(name="start-client")
@click.option('--server-host', default='localhost', help='Host do servidor')
@click.option('--server-port', default=65432, help='Porta do servidor')
@click.option('--private-key-file', default='private_client_key.pem', help='Caminho para o arquivo da chave privada')
@click.option('--public-key-file', default='public_client_key.pem', help='Caminho para o arquivo da chave pública')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Senha para a chave privada')
@click.option('--watch-path', default='./share-client', help='Pasta para monitorar com o Watchdog')
def start_client(server_host, server_port, private_key_file, public_key_file, password, watch_path):

    """Inicia o servidor seguro para comunicação e o watchdog para monitorar a pasta especificada"""
    client = Client(server_host, server_port, private_key_file, public_key_file, password, watch_path)
    
    # Start the watchdog to monitor the specified path
    start_watchdog(watch_path, client=client, server=None)
    

@dteam.command()
@click.option('--file_path', default='./share-server/teste.txt.enc', help='Arquivo para mostrar o conteudo original')
@click.option('--private-key-file', default='private_client_key.pem', help='Caminho para o arquivo da chave privada')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Senha para a chave privada')
def decrypt(file_path, private_key_file, password):

    with open('received_key', 'rb') as f:
        encrypted_key = f.read()

    decrypt_file(file_path, private_key_file, password, encrypted_key)

    decrypted_filename = file_path.replace(".enc", ".dec")
    with open(decrypted_filename, "r") as f:
        plaintext = f.read()
        print("Decrypted content:", plaintext)

@dteam.command()
def test():
    # Exemplo de uso
    private_key_file = 'private_key.pem'
    public_key_file = 'public_key.pem'
    password = 'mypassword1'
    filename = 'teste.txt'

    if os.path.isfile(private_key_file):
        try:
            os.remove(private_key_file)
            print(f"Arquivo '{private_key_file}' deletado com sucesso.")
        except PermissionError:
            print(f"Permissão negada ao tentar deletar o arquivo '{private_key_file}'.")
        except Exception as e:
            print(f"Ocorreu um erro ao deletar o arquivo: {e}")
    else:
        print(f"O arquivo '{private_key_file}' não foi encontrado.")

    if os.path.isfile(public_key_file):
        try:
            os.remove(public_key_file)
            print(f"Arquivo '{public_key_file}' deletado com sucesso.")
        except PermissionError:
            print(f"Permissão negada ao tentar deletar o arquivo '{public_key_file}'.")
        except Exception as e:
            print(f"Ocorreu um erro ao deletar o arquivo: {e}")
    else:
        print(f"O arquivo '{public_key_file}' não foi encontrado.")

    generate_keys(private_key_file, public_key_file, password)
    encrypted_key = encrypt_file(filename, public_key_file)
    decrypt_file(filename + '.enc', private_key_file, password, encrypted_key)

    sign_file(filename,private_key_file,password.encode('utf-8'))
    verify_signature(filename,public_key_file, filename + '.sig')

if __name__ == '__main__':
    dteam()
