import typer

from observatory.observer import Observer

app = typer.Typer()


@app.command(
    name="sniff",
    epilog="Runs a packet sniffer with the given details and shows packet details",
)
def sniff(
    bp_filters: str = None,
    sniff_count: int = 0,
    extra_questions: str = None,
):
    if extra_questions:
        extra_questions = extra_questions.strip().split(",")

    observer = Observer(
        sniff_count=sniff_count, bp_filters=bp_filters, extra_questions=extra_questions
    )
    observer.observe()


if __name__ == "__main__":
    app()
