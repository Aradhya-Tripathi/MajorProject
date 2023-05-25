import click

from cli.main import extra_kwargs, netscanner_commands


@netscanner_commands.group()
def realtime():
    ...


@realtime.command(
    "dashboard",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Triggers a realtime dashboard showcasing the network activity",
)
@click.option("--capture-duration", type=str, default="0.5 second")
@click.option("--classification-rate", type=float, default=0.5)
@click.pass_obj
@click.pass_context
def dashboard(
    ctx: dict,
    verbose: bool,
    capture_duration: str = "0.5 second",
    classification_rate: float = 0.5,
) -> None:
    from src.ip.realtime import Realtime

    kwargs = {}
    extra_kwargs(ctx, kwargs)

    Realtime(
        classification_rate=classification_rate, verbose=verbose, **kwargs
    ).dashboard(capture_duration=capture_duration)


@realtime.command(
    "monitor",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Runs a realtime monitor scanning all packets also classifies them as safe or unsafe depending on the classification rate",
)
@click.option("--duration", type=str, default=None)
@click.option("--wait-for", type=int, default=1)
@click.option("--notify", is_flag=True, default=False)
@click.pass_obj
@click.pass_context
def monitor(
    ctx: dict,
    verbose: bool,
    duration: str = None,
    wait_for: int = 1,
    notify: bool = False,
    classification_rate: float = 0.5,
) -> None:
    from src.ip.realtime import Realtime

    kwargs = {}
    extra_kwargs(ctx, kwargs)
    Realtime(
        duration=duration,
        wait_for=wait_for,
        notify=notify,
        classification_rate=classification_rate,
        verbose=verbose,
        **kwargs,
    ).monitor()
