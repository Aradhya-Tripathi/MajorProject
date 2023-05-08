import json
import os
import time
from pathlib import Path
from typing import Any

from cli.renderer import console
from src.utils import Json


class HistoryObject(dict):
    def __getattribute__(self, __name: str) -> Any:
        return super().__getitem__(__name)


class HistoryResult(list):
    def __init__(self, _iterable) -> None:
        _iterable = map(HistoryObject, _iterable)
        super().__init__(_iterable)


class History:
    def __init__(self, history_path: str = None, save_all: bool = False) -> None:
        self.history_path = (
            history_path
            if history_path
            else os.path.join((Path(__file__).parent.resolve()), "history.json")
        )
        self.writes = 0
        self.save_all = save_all
        self.supported_filters = {
            "src",
            "dst",
            "is_safe",
            "protocal",
            "dport",
            "sport",
        }

        console.print(
            f"Storing history in: {os.path.abspath(os.path.expanduser(self.history_path))}",
            style="red",
        )

        if os.path.isfile(self.history_path):
            with open(self.history_path, "r+") as f:
                self.history = Json(json.loads(f.read()))
        else:
            self.history = Json()

    def exists(self, src: str) -> bool:
        for instance in self.history:
            if instance["packet_info"]["src"] == src:
                return True

        return False

    def add(
        self,
        src: str,
        dst: str,
        is_safe: bool = None,
        dport: str = None,
        sport: str = None,
        protocal: str = None,
    ) -> None:
        if self.writes >= 1:
            self.history.save(self.history_path)

        if not self.save_all:
            if self.exists(src=src):
                return

        self.history.append(
            {
                "time": time.time(),
                "packet_info": dict(
                    src=src,
                    dst=dst,
                    is_safe=is_safe,
                    dport=dport,
                    sport=sport,
                    protocal=protocal,
                ),
            }
        )

        self.writes += 1

    def process_filter(self, filters: dict[str, str]):
        results = []
        for instance in self.history:
            for k, v in filters.items():
                if k not in self.supported_filters:
                    raise ValueError(f"{k} filter is not supported!")

                if instance["packet_info"][k] == v:
                    results.append(instance)

        return results

    def get(self, filters: dict = None) -> HistoryResult:
        history_result = None
        if filters:
            history_result = self.process_filter(filters)
        else:
            history_result = self.history

        if history_result:
            if len(history_result) == 1:
                return HistoryObject(history_result[0])

            return HistoryResult(history_result)

    def save(self) -> None:
        self.history.save(self.history_path)


if __name__ == "__main__":
    h = History()
