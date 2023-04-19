# File to represent networking patterns.
"""
Implement a real-time dashboard that provides a visual overview of network activity, including traffic volume, top talkers, and most common protocols

"""
from src.ip.model.cache import get_cache


class History:
    def __init__(self) -> None:
        self.cache = get_cache()

    def add(self, src: str, dst: str, timestamp: str, is_safe: bool) -> None:
        """
        Add packet information to redis cache.
        """
        self.cache.hset(
            name=src,
            mapping={
                "dst_ip": dst,
                "timestamp": timestamp,
                "is_safe": int(is_safe),
            },
        )

    def exists(self, src: str) -> bool:
        return bool(self.cache.exists(src))

    def get_by_src(self, src: str) -> str:
        res = self.cache.hgetall(src)
        for k, v in res.items():
            if k == "is_safe":
                res[k] = bool(int(v))

        return res

    def clear(self):
        self.cache.flushdb()


if __name__ == "__main__":
    history = History()
