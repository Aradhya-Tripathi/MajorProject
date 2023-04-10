import json
import os
import re
import signal
import threading
from datetime import datetime
from pathlib import Path

SRC_PATTERN = re.compile(r"\bsrc\b\s+(\S+)")


def load_env(root_path: str = None):
    # Decent alternative for load env (excess deps)
    root_path = (
        os.path.join(Path(__file__).parent.resolve(), ".env")
        if not root_path
        else root_path
    )
    try:
        with open(root_path, "r") as f:
            env_data = f.read().strip().replace(" ", "").split()
            for data in env_data:
                key, value = data.split("=")
                os.environ[key] = value
    except FileNotFoundError:
        raise EnvironmentError(
            "Set the environment variables using <netscanner utils set-env-variables first"
        )


def convert_unix_timestamp(timestamp: float) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_src(bp_filters: str) -> str:
    if ip := SRC_PATTERN.findall(bp_filters):
        return ip[0]


def set_env(vars: list, root_path: str = None):
    env_vars_keys = ["AbuseIPDb-Key", "ip2location", "chatapi"]

    for idx, keys in enumerate(env_vars_keys, start=0):
        vars[idx] = keys + "=" + vars[idx]

    root_path = (
        os.path.join(Path(__file__).parent.resolve(), ".env")
        if not root_path
        else root_path
    )

    with open(root_path, "w") as f:
        f.write("\n".join(vars))


class Json(dict):
    def save(self, path: str):
        with open(path, "w+") as f:
            f.write(json.dumps(self, indent=2))


class Timeout:
    def __init__(self, seconds: int, kill_func: callable = None) -> None:
        self.seconds = seconds
        self.kill_func = kill_func

    def kill(self, pid: int):
        print("\n\033[1m\033[93mCall timed out!")
        os.kill(pid, signal.SIGINT)

    def __enter__(self):
        if self.seconds:
            func = self.kill_func if self.kill_func else self.kill
            self.killing_thread = threading.Timer(
                self.seconds, function=func, kwargs={"pid": os.getpid()}
            )
            self.killing_thread.start()

    def __exit__(self, *args, **kwargs):
        if self.seconds:
            self.killing_thread.cancel()
