import redis
import os

host, port = os.getenv("cache_host", "localhost"), os.getenv("cache_port", 6379)


def get_cache() -> redis.Redis:
    return redis.Redis(host=host, port=port, decode_responses=True)
