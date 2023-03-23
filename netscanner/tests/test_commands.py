import shlex
import subprocess
from unittest import TestCase


def load_commands(path_to_commands: str = "./commands.txt") -> list:
    commands = []

    with open(path_to_commands) as f:
        text_commands = f.read().strip().split("\n")

    for cmd in text_commands:
        if not cmd or cmd.startswith("#"):
            continue
        commands.append(cmd)

    return commands


class TestCommands(TestCase):
    commands = load_commands()

    def test_commands(self):
        for command in self.commands:
            results = subprocess.check_output(
                shlex.split(command), universal_newlines=True
            )
            print(results)
