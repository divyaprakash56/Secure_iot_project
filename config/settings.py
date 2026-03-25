import os
from dotenv import load_dotenv, set_key

load_dotenv()

ENV_FILE = ".env"


class KeyManager:
    def __init__(self, total_nodes=5):
        self.total_nodes = total_nodes
        self.node_keys = {}  # {node_id: {version: key}}
        self.load_keys()

    def load_keys(self):
        for node_id in range(1, self.total_nodes + 1):

            self.node_keys[node_id] = {}

            env_key = f"NODE_{node_id}_KEY_v1"
            key_hex = os.getenv(env_key)

            if key_hex:
                self.node_keys[node_id][1] = bytes.fromhex(key_hex)
            else:
                new_key = os.urandom(32)
                self.node_keys[node_id][1] = new_key

                set_key(ENV_FILE, env_key, new_key.hex())
                print(f"[SECURITY] Generated key for NODE_{node_id} (v1)")

    def get_key(self, node_id, version=None):
        versions = self.node_keys.get(node_id)

        if not versions:
            raise ValueError("Invalid node")

        if version is None:
            version = max(versions.keys())

        if version not in versions:
            raise ValueError("Invalid key version")

        return versions[version]

    def rotate_key(self, node_id):
        if node_id not in self.node_keys:
            raise ValueError("Invalid node ID")

        versions = self.node_keys[node_id]

        new_version = max(versions.keys()) + 1
        new_key = os.urandom(32)

        versions[new_version] = new_key

        env_key = f"NODE_{node_id}_KEY_v{new_version}"
        set_key(ENV_FILE, env_key, new_key.hex())

        print(f"[SECURITY] Key rotated for NODE_{node_id} (v{new_version})")

        return new_key, new_version


# Singleton
key_manager = KeyManager()