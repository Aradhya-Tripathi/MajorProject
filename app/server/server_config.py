import time
import typing

from fastapi.responses import HTMLResponse
from gradio.networking import Server
from gradio.routes import App
from uvicorn.config import Config

if typing.TYPE_CHECKING:
    from fastapi.requests import Request
    from gradio import Blocks


def init_server(
    app: "Blocks",
    host: str = "0.0.0.0",
    port: int = 8080,
    debug: bool = False,
) -> Server:
    """
    Adds an extra middleware to the gradio app to disable browser view,
    and only allow desktop view.
    """
    app = App.create_app(blocks=app)

    @app.middleware("http")
    async def _(request: "Request", call_next):
        if (
            "This will be replaced by an external API call most likey"
            not in request.headers.get("x-custom-header", "")
        ):
            return HTMLResponse(content="<H1>Permission Denied<H1>", status_code=403)
        response = await call_next(request)
        return response

    config = Config(
        app=app,
        host=host,
        port=port,
        reload_delay=5,
        log_level=10 if debug else 50,
    )
    server = Server(config=config)
    server.run_in_thread()
    try:
        while True:
            time.sleep(0.1)
    except (KeyboardInterrupt, OSError):
        server.close()
