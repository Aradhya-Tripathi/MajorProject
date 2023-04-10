# This file is to handle background sniffing and or classifying and reporting the same.

import json
import os
import random
import shlex
import signal
import subprocess
import sys
from datetime import datetime

import redis
from scapy import all as modules

from cli.renderer import console
from src.ip.classification.abuseip_classification import AbuseIPClassification
from src.sniff.sniff import Sniffer


class Reporter:
    hash_name = "Records"
    lock_name = f"/tmp/{__name__}.lock"

    def __init__(
        self,
        duration: int = None,
        wait_for: int = None,
        notify: bool = False,
        host: str = "localhost",
        port: int = 6379,
        verbose: bool = False,
        **kwargs,
    ) -> None:
        self.duration = duration
        self.wait_for = wait_for
        self.verbose = verbose
        self.kwargs = kwargs
        self.sniffer = None
        self.cache = redis.Redis(host=host, port=port)

        if sys.platform != "darwin":
            raise OSError("Only supports notifcation for darwin systems")

        self.notify = notify
        self.setup()
        self.report()

    def setup(self) -> None:
        if os.path.isfile(self.lock_name):
            raise OSError(
                "Program is already running kill all instances of the program before starting."
            )
        with open(self.lock_name, "w+") as lock_file:
            lock_file.write(str(os.getpid()))

        for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]:
            signal.signal(sig, self.signal_handler)

    def signal_handler(self, *arg):
        self.cleanup()

    def submit_report(
        self, src_ip: str, dst_ip: str, timestamp: str, is_safe: bool
    ) -> None:
        self.cache.hset(
            self.hash_name,
            key=src_ip,
            value=json.dumps(
                {"dst_ip": dst_ip, "timestamp": timestamp, "is_safe": is_safe}
            ),
        )

    def send_notification(self, packet_src: str) -> None:
        message = f"Unsafe packet detected from {packet_src}"
        command = (
            f'display notification "{message}" with title "Unsafe packet detected"'
        )
        subprocess.run(shlex.split(f"osascript -e '{command}'"))
        self.notified = True

    def is_submitted(self, src_ip: str) -> bool:
        return self.cache.hexists(self.hash_name, src_ip)

    def report(self) -> None:
        forbidden_requests = ["show_packets", "send_request"]
        for request in forbidden_requests:
            self.kwargs.pop(request, None)

        self.kwargs["verbose"] = False
        self.kwargs["is_async"] = True
        console.print(
            "\n[italic]Starting sniffer and streaming packets\n",
            style="info",
            verbose=self.verbose,
        )
        self.sniffer = Sniffer(**self.kwargs)

        for packet in self.sniffer.stream_packets(
            duration=self.duration, wait_for=self.wait_for
        ):
            packet = packet[modules.IP]
            # 50/50 process further or return also no duplicate src IPs stored.
            if self.is_submitted(packet.src) or random.choice([True, False]):
                continue

            is_safe = (
                AbuseIPClassification(packet.src).report()["abuseConfidenceScore"] < 50
            )
            if not is_safe and self.notify:
                self.send_notification(packet_src=packet.src)

            self.submit_report(
                src_ip=packet.src,
                dst_ip=packet.dst,
                timestamp=str(datetime.now()),
                is_safe=is_safe,
            )

        self.cleanup()

    def cleanup(self) -> None:
        console.print("Cleaning up", style="info", verbose=self.verbose)
        self.sniffer.stop()
        if os.path.isfile(self.lock_name):
            os.unlink(self.lock_name)
