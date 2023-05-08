import json
import os
import re
import signal
import threading
from datetime import datetime, timedelta
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


class Json(list):
    def save(self, path: str):
        with open(path, "w") as f:
            f.write(json.dumps(self, indent=2))


# parse the time duration string
def parse_duration(duration: str = None) -> float:
    if not duration:
        return 0.0
    try:
        duration_parts = duration.split()
        duration_value = float(duration_parts[0])
        duration_unit = duration_parts[1]
    except IndexError:
        raise Exception(f"Invalid duration format {duration} format: <duration unit>")

    # convert the time duration to seconds
    if duration_unit == "day":
        duration_seconds = timedelta(days=duration_value).total_seconds()
    elif duration_unit == "hour":
        duration_seconds = timedelta(hours=duration_value).total_seconds()
    elif duration_unit == "minute":
        duration_seconds = timedelta(minutes=duration_value).total_seconds()
    elif duration_unit == "second":
        duration_seconds = duration_value
    elif duration_unit == "week":
        duration_seconds = timedelta(weeks=duration_value).total_seconds()
    else:
        raise ValueError(f"Invalid duration unit: {duration_unit}")

    return duration_seconds


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
