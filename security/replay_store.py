import json
import os

FILE_PATH = "replay_store.json"


class ReplayStore:

    def __init__(self):

        if not os.path.exists(FILE_PATH):
            with open(FILE_PATH, "w") as f:
                json.dump({}, f)

        with open(FILE_PATH, "r") as f:
            self.store = json.load(f)   # ✅ MUST exist

    def is_replay(self, node_id, nonce_hex):

        node = str(node_id)

        if node not in self.store:
            self.store[node] = []

        return nonce_hex in self.store[node]

    def add_nonce(self, node_id, nonce_hex):

        node = str(node_id)

        if node not in self.store:
            self.store[node] = []

        self.store[node].append(nonce_hex)

        # keep last 100
        self.store[node] = self.store[node][-100:]

        self._save()

    def _save(self):
        with open(FILE_PATH, "w") as f:
            json.dump(self.store, f)