from watchdog.events import FileSystemEventHandler
from security_util import sign_file, encrypt_file

import os
import time


class WatchdogHandler(FileSystemEventHandler):
    def __init__(self, client=None, server=None):
        self.client = client
        self.server = server

    def on_modified(self, event):
        print(f'Arquivo modificado: {event.src_path}')

    def on_created(self, event):
        print(f'Arquivo criado: {event.src_path}')

        if event.is_directory:
            return None

        elif event.event_type == 'created' and not event.src_path.endswith(".enc") and not event.src_path.endswith(".sig"):
            
            print(f"Received created event - {event.src_path}.")
            
            while not os.path.exists(event.src_path) or os.path.getsize(event.src_path) == 0:
                time.sleep(0.1)
            time.sleep(1)
       
            if self.client:
                encrypted_key = encrypt_file(event.src_path, self.client.public_key_file)
                self.client.handle_new_file(event.src_path + ".enc", encrypted_key)

            elif self.server:
                encrypted_key = encrypt_file(event.src_path, self.server.public_key_file)
                self.server.handle_new_file(event.src_path + ".enc", encrypted_key)

            os.remove(event.src_path)


    def on_deleted(self, event):
        print(f'Arquivo excluído: {event.src_path}')

