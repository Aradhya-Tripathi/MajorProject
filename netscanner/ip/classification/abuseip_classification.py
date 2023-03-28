import os
from concurrent.futures import ThreadPoolExecutor

from netscanner.ip import session

api_url = "https://api.abuseipdb.com/api/v2/check"
headers = {"Accept": "application/json", "Key": os.getenv("AbuseIPDb-Key")}


class AbuseIPClassification:
    def __init__(self, address: str | list[str]):
        self.address = address
        if isinstance(self.address, list) and len(self.address) == 1:
            self.address = self.address[0]

    def _classify(self, src: str) -> dict[str, str]:
        params = {"ipAddress": src}

        response = session.get(
            url=api_url,
            headers=headers,
            params=params,
        )
        response = response.json()

        if "data" not in response:
            raise Exception(
                f"Details about this Ip address {src} not found in the database!"
            )

        return response["data"]

    def report(self) -> dict[str, str] | map:
        if isinstance(self.address, str):
            return self._classify(self.address)

        with ThreadPoolExecutor() as executor:
            return executor.map(self._classify, self.address)
