import os
from pathlib import Path


def load_env(root_path: str = "./.env"):
    # Decent alternative for load env (excess deps)
    root_path = (
        os.path.join(Path(__file__).parent.parent.resolve(), ".env")
        if not root_path
        else root_path
    )
    with open(root_path, "r") as f:
        env_data = f.read().strip().replace(" ", "").split()
        for data in env_data:
            key, value = data.split("=")
            os.environ[key] = value
