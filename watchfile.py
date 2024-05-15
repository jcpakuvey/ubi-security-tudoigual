import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from security_util import encrypt_file  # Importação da função encrypt_file do módulo cryptography

import os

class Watcher:
    DIRECTORY_TO_WATCH = "./share"

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()

class Handler(FileSystemEventHandler):

    @staticmethod
    def on_created(event):
        if event.is_directory:
            return None

        elif event.event_type == 'created' and not event.src_path.endswith(".enc") :
            # Take any action here when a file is created.
            print(f"Received created event - {event.src_path}.")
            # Call your encryption function here
            encrypt_file(event.src_path, "public_key.pem")
            os.remove(event.src_path)

if __name__ == "__main__":
    w = Watcher()
    w.run()