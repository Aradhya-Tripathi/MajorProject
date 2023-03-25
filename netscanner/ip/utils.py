import shlex
import socket
import subprocess

from renderer import console


QUESTIONS = [
    "dst",
    "src",
    "ttl",
    "proto",
    "chksum",
    "seq",
    "ack",
    "urgptr",
    "sport",
    "dport",
    "time",
    "payload",
]


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


def proto_lookup() -> dict[int, str]:
    """
    Returns the protocal associated with it's corresponding protocal number according to IANA.
    """
    lookup = {}
    prefix = "IPPROTO_"

    for proto, number in vars(socket).items():
        if proto.startswith(prefix):
            lookup[number] = proto[len(prefix) :]

    return lookup
