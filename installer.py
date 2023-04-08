"""
This file is to allow easy install and setup of the cli and the dekstop app,
only written for easy demonstration.
"""
import os
import shlex
import subprocess
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform not in ("darwin", "linux")


def run(
    cmd: str,
    stdout: int = subprocess.DEVNULL,
    cwd: str = ".",
    stdin: int = sys.stdin,
    stderr: int = subprocess.DEVNULL,
):
    print(f"$ {cmd}")
    subprocess.check_call(
        shlex.split(cmd), cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr
    )


class Installer:
    __slots__ = ("source", "clone_path", "python", "pip", "env", "system", "only_cli")

    def __init__(self, clone_path: str, only_cli: bool = True) -> None:
        if is_windows():
            raise OSError("Does not support windows yet.")

        self.source = "https://github.com/Aradhya-Tripathi/MajorProject.git"
        self.clone_path = os.path.abspath(os.path.expanduser(clone_path))
        self.system = sys.platform
        self.only_cli = only_cli
        self.install()

    @property
    def in_virtual_environment(self) -> bool:
        return sys.prefix != sys.base_prefix

    @property
    def project_exists(self) -> bool:
        if not os.path.exists(self.clone_path):
            return False

        for dir in os.scandir(self.clone_path):
            if dir.name == "netscanner":
                return True

        return False

    @property
    def has_npm(self) -> bool:
        try:
            run("npm -v")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def install_npm(self) -> None:
        if self.has_npm:
            print("skipping npm installation")
            return

        manager = "apt" if self.system == "linux" else "brew"
        run(f"{manager} install npm")

    def create_environment(self) -> None:
        if not self.in_virtual_environment:
            run(f"python3 -m venv {os.path.join(self.clone_path, 'env')}")
            self.python = os.path.join(self.clone_path, "env", "bin", "python")
            print("Created virtual environment")

        else:
            print("Skipping virtual environment creation")
            self.python = os.path.join(sys.prefix, "bin", "python")

        self.pip = os.path.join(str(Path(self.python).parent), "pip")
        self.env = str(Path(self.python).parent.parent)

    def clone(self) -> None:
        if not self.project_exists:
            run(f"git clone {self.source} {self.clone_path}")
        else:
            print("Skipping clone as project exists")

    def install_requirement(self) -> None:
        install_cmd = f"{self.pip} install ."
        if not self.only_cli:
            install_cmd += " gradio"

        run(install_cmd, cwd=self.clone_path)
        if not self.only_cli:
            run("npm install --save electron", cwd=os.path.join(self.clone_path, "app"))

    def install(self) -> None:
        self.clone()
        self.create_environment()
        if not self.only_cli:
            self.install_npm()
        self.install_requirement()
        print(
            f"netscanner --help to get started or cd {os.path.join(self.clone_path, 'app')} && electron ."
        )


if __name__ == "__main__":
    try:
        clone_path = sys.argv[1]
    except IndexError:
        clone_path = "./new"

    Installer(clone_path=clone_path)
