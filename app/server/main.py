import gradio as gr
from api import classify_ip, traceroute, traceroute_and_classify
from server_config import init_server

with gr.Blocks(
    title="Major Project",
    theme=gr.themes.Soft(),
) as main:
    # Main app handler uses FastAPI under the hood.
    main.show_api = False
    main.show_error = True

    traceroute_headers = [
        "IP Address",
        "Country",
        "Region",
        "City",
        "Latitude",
        "Longitude",
        "Zip Code",
    ]

    gr.Markdown(
        """
    # Packet classification app.
    ## This can be used from tracing packet route and also classifying them.
    ### However for a more comprehensive view use the command line application.
     """
    )

    with gr.Tab(label="Single Packet Classification"):
        ip_address = gr.Textbox(
            label="IP Address",
            placeholder="Enter an IPv4 address to classify.",
        )
        classification_results = gr.DataFrame(
            headers=[
                "IP Address",
                "Confidance Score",
                "Country",
                "Internet service provider",
                "Is public",
            ],
        )
        classify_button = gr.Button("Classify IP Address")
        classify_button.click(
            classify_ip,
            inputs=ip_address,
            outputs=[classification_results],
        )

    with gr.Tab(label="Trace IP packet route"):
        destination_ip = gr.Textbox(
            label="Destination IP Address",
            placeholder="Enter a destination IP to trace route.",
        )

        traceroute_results = gr.DataFrame(headers=traceroute_headers)
        traceroute_button = gr.Button("Traceroute")
        traceroute_button.click(
            traceroute,
            inputs=destination_ip,
            outputs=traceroute_results,
        )

    with gr.Tab(label="Trace IP packet route and classify nodes"):
        destination_ip = gr.Textbox(
            label="Destination IP Address",
            placeholder="Enter a destination IP to trace route.",
        )

        traceroute_headers.append("Classification")
        traceroute_and_classify_results = gr.DataFrame(headers=traceroute_headers)
        traceroute_and_classify_button = gr.Button("Traceroute and Classify")
        traceroute_and_classify_button.click(
            traceroute_and_classify,
            inputs=destination_ip,
            outputs=traceroute_and_classify_results,
        )

    with gr.Tab(label="Network traffic classification"):
        sniff_count = gr.Number(
            label="Sniff count",
            placeholder="Number of packets to transfer.",
        )


if __name__ == "__main__":
    import sys

    try:
        secret_key = sys.argv[1]
    except IndexError:
        raise Exception("Enter secret key")

    init_server(app=main, secret_key=secret_key)
