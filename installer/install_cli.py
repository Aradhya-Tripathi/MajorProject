"""
This file is to allow easy install and setup of the cli application.
"""
import os
import shlex
import subprocess
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform not in ("darwin", "linux")


def in_virtual_environment() -> bool:
    return sys.prefix != sys.base_prefix


class Installer:
    __slots__ = (
        "source",
        "clone_path",
        "in_virtual_environment",
        "python",
        "pip",
        "env",
    )

    def __init__(self, clone_path: str) -> None:
        if is_windows():
            raise OSError("Does not support windows yet.")

        self.source = "https://github.com/Aradhya-Tripathi/MajorProject.git"
        self.in_virtual_environment = in_virtual_environment()
        self.clone_path = os.path.abspath(os.path.expanduser(clone_path))

    def create_environment(self) -> None:
        if not self.in_virtual_environment:
            subprocess.check_call(
                shlex.split(f"python3 -m venv {os.path.join(self.clone_path, 'env')}"),
                stdout=subprocess.DEVNULL,
            )
            self.python = os.path.join(self.clone_path, "env", "bin", "python")
            print("Created virtual environment")

        else:
            print("Skipping virtual environment creation")
            self.python = os.path.join(sys.prefix, "bin", "python")

        self.pip = os.path.join(str(Path(self.python).parent), "pip")
        self.env = str(Path(self.python).parent.parent)

    def clone(self) -> None:
        subprocess.check_call(
            shlex.split(f"git clone {self.source} {self.clone_path}"),
            stdout=subprocess.DEVNULL,
        )

    def install_requirement(self):
        subprocess.check_call(shlex.split(f"{self.pip} install ."), cwd=self.clone_path)

    def install(self):
        self.clone()
        self.create_environment()
        self.install_requirement()
        print("netscanner --help to get started.")


if __name__ == "__main__":
    Installer(clone_path="./new").install()
