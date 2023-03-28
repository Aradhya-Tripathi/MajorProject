import socket
import time
import typing
from contextlib import closing

from fastapi.responses import HTMLResponse
from gradio.networking import Server
from gradio.routes import App
from uvicorn.config import Config

if typing.TYPE_CHECKING:
    from fastapi.requests import Request
    from gradio import Blocks


def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            raise ConnectionError(f"Port is in use!: {host}:{port}")


def init_server(
    app: "Blocks",
    secret_key: str,
    host: str = "0.0.0.0",
    port: int = 8080,
    debug: bool = False,
) -> None:
    """
    Adds an extra middleware to the gradio app to disable browser view,
    and only allow desktop view.
    """
    app = App.create_app(blocks=app)

    check_socket(host=host, port=port)

    @app.middleware("http")
    async def _(request: "Request", call_next):
        if secret_key != request.headers.get("x-custom-header", ""):
            return HTMLResponse(content="<H1>Permission Denied<H1>", status_code=403)
        response = await call_next(request)
        return response

    config = Config(
        app=app,
        host=host,
        port=port,
        log_level=10 if debug else 50,
    )
    server = Server(config=config)
    server.run_in_thread()

    if not debug:
        print("[INFO] Server Running")
    try:
        while True:
            time.sleep(0.1)
    except (KeyboardInterrupt, OSError):
        server.close()
