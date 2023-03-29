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

ABUSEIP_UNWANTED = [
    "ipVersion",
    "hostnames",
    "numDistinctUsers",
    "lastReportedAt",
    "totalReports",
    "isWhitelisted",
]


def private_ip(verbose: bool = True):
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

    console.print(f"[cyan]Private IP address is: [bold]{ip}", verbose=verbose)
    return ip


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


def redundant_api_ip_details(
    ip_list: list[str], intermediate_node_details: dict[str, str]
) -> dict[str, str]:
    from netscanner.ip import session

    console.print(
        "[red][bold]Some IP locations were not found in the databases querying esternal services..."
    )
    response = session.post(
        "http://ip-api.com/batch", json=[{"query": ip} for ip in ip_list]
    )

    if not response.ok:
        console.print(
            "Redundant method failed location could not be found.", style="bold red"
        )
        exit(-1)

    response = response.json()
    console.print("[green]Found results using external services!")
    for idx, res in enumerate(response, start=0):
        intermediate_node_details[ip_list[idx]] = dict(
            country_name=res.get("country"),
            region_name=res.get("regionName"),
            city_name=res.get("city"),
            latitude=res.get("lat"),
            longitude=res.get("lon"),
            field8=res.get("zip"),
        )
