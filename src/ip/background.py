# This file is to handle background sniffing and or classifying and reporting the same.

import json
import random
import shlex
import subprocess
import sys
from datetime import datetime

import redis
from scapy import all as modules

from src.ip.classification.abuseip_classification import AbuseIPClassification
from src.sniff.sniff import Sniffer


class Reporter:
    hash_name = "Records"

    def __init__(
        self,
        duration: int = None,
        wait_for: int = None,
        notify: bool = False,
        host: str = "localhost",
        port: int = 6379,
        **kwargs,
    ) -> None:
        self.duration = duration
        self.wait_for = wait_for
        self.kwargs = kwargs
        self.sniffer = None
        self.notified = False
        self.cache = redis.Redis(host=host, port=port)

        if sys.platform != "darwin":
            raise OSError("Only supports notifcation for darwin systems")

        self.notify = notify
        self.report()

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
            if not is_safe and self.notify and not self.notified:
                self.send_notification(packet_src=packet.src)

            self.submit_report(
                src_ip=packet.src,
                dst_ip=packet.dst,
                timestamp=str(datetime.now()),
                is_safe=is_safe,
            )
