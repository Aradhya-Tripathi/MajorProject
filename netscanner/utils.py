import os
import re
from datetime import datetime
from pathlib import Path

SRC_PATTERN = re.compile(r"\bsrc\b\s+(\S+)")


def load_env(root_path: str = "./netscanner/.env"):
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


def convert_unix_timestamp(timestamp: float) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_src(bp_filters: str) -> str:
    if ip := SRC_PATTERN.findall(bp_filters):
        return ip[0]
