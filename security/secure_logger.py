import hashlib
import os

LOG_FILE = "secure_logs.txt"


class SecureLogger:

    def __init__(self):
        self.prev_hash = self._get_last_hash()

    def _get_last_hash(self):

        if not os.path.exists(LOG_FILE):
            return "0" * 64

        with open(LOG_FILE, "r") as f:
            lines = f.readlines()

        if not lines:
            return "0" * 64

        last_line = lines[-1].strip()

        try:
            return last_line.split("|")[-1]
        except:
            return "0" * 64

    def log(self, message):

        data = self.prev_hash + message
        new_hash = hashlib.sha256(data.encode()).hexdigest()

        log_entry = f"{message} | {new_hash}"

        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

        self.prev_hash = new_hash


# singleton
secure_logger = SecureLogger()