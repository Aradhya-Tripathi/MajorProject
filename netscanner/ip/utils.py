import shlex
import subprocess

from netscanner.ip import console


def private_ip():
    """Returns current networks private IP"""
    ifconfig = subprocess.Popen(shlex.split("ifconfig"), stdout=subprocess.PIPE)
    inet = subprocess.Popen(
        shlex.split("grep 'inet '"), stdin=ifconfig.stdout, stdout=subprocess.PIPE
    )
    localhost = subprocess.Popen(
        shlex.split("grep -Fv 127.0.0.1"), stdin=inet.stdout, stdout=subprocess.PIPE
    )
    ip = subprocess.check_output(
        shlex.split("awk '{print $2}'"), stdin=localhost.stdout
    ).decode()

    console.print(f"[cyan]Private IP address is: [bold]{ip}")


def public_ip(show: bool = True) -> str:
    "Retuns current networks public IP"
    dev_null = open("/dev/null")
    ip = subprocess.check_output(
        shlex.split("curl ifconfig.me"), stderr=dev_null
    ).decode()
    dev_null.close()
    if show:
        console.print(f"[cyan]Public IP address is: [bold]{ip}")
    return ip


def trackcalls(func):
    def inner(*args, **kwargs):
        inner.has_been_called = True
        return func(*args, **kwargs)

    inner.has_been_called = False
    return inner
