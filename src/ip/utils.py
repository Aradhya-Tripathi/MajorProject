import shlex
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from cli.renderer import console

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
    "length",
]

ABUSEIP_UNWANTED = [
    "ipVersion",
    "hostnames",
    "numDistinctUsers",
    "lastReportedAt",
    "totalReports",
    "isWhitelisted",
]


PORT_MAPPINGS = {
    80: "http",
    25: "smtp",
    79: "finger",
    53: "domain",
    113: "auth",
    23: "telnet",
    21: "ftp",
    144: "eco_i",
    123: "ntp_u",
    255: "ecr_i",
    0: "private",
    110: "pop_3",
    20: "ftp_data",
    77: "rje",
    37: "tim_i",
    57: "mtp",
    245: "link",
    87: "remote_job",
    70: "gopher",
    22: "ssh",
    42: "name",
    43: "whois",
    513: "login",
    143: "imap4",
    13: "daytime",
    105: "csnet_ns",
    119: "nnsp",
    514: "shell",
    194: "IRC",
    443: "http_443",
    512: "exec",
    515: "printer",
    520: "efs",
    530: "courier",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    7: "echo",
    9: "discard",
    11: "systat",
    95: "supdup",
    102: "iso_tsap",
    101: "hostnames",
    109: "pop_2",
    111: "sunrpc",
    117: "uucp_path",
    137: "netbios_ns",
    139: "netbios_ssn",
    138: "netbios_dgm",
    118: "sql_net",
    2389: "vmnet",
    179: "bgp",
    210: "Z39_50",
    389: "ldap",
    15: "netstat",
    1190: "urh_i",
    6000: "X11",
    556: "urp_i",
    1001: "pm_dump",
    69: "tftp_u",
    112: "red_i",
}


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
    return ip.strip()


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
    from src.ip import session

    response = session.post(
        "http://ip-api.com/batch", json=[{"query": ip} for ip in ip_list]
    )

    if not response.ok:
        console.print(
            "Redundant method failed location could not be found.", style="bold red"
        )
        exit(-1)

    response = response.json()
    for idx, res in enumerate(response, start=0):
        intermediate_node_details[ip_list[idx]] = dict(
            country_name=res.get("country"),
            region_name=res.get("regionName"),
            city_name=res.get("city"),
            latitude=res.get("lat"),
            longitude=res.get("lon"),
            zip_code=res.get("zip"),
        )


def ports_in_use(
    host: str,
    start: int,
    end: int,
    max_workers: int = 100,
    verbose: bool = True,
) -> dict[str, str]:
    ports = {}
    lock = Lock()

    def _connect(port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        if sock.connect_ex((host, port)) == 0:
            port = str(port)
            lock.acquire()
            ports[port] = PORT_MAPPINGS.get(port, "Unknown")
            lock.release()

    with console.status(
        f"Scanning open ports on {host}", spinner="bouncingBall", verbose=verbose
    ):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(_connect, range(start, end))

    return ports


def hostname(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.gaierror, socket.herror):
        return ip
