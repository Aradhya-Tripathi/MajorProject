import gradio as gr
from api import classify_ip, traceroute
from server_config import init_server

with gr.Blocks(title="Major Project") as main:
    # Main app handler uses FastAPI under the hood.
    main.show_api = False
    main.show_error = False

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
                "Confidance Score",
                "Country",
                "Internet service provider",
                "Is public",
            ],
        )
        classify_button = gr.Button("Classify IP Address")
        classify_button.click(
            classify_ip, inputs=ip_address, outputs=classification_results
        )

    with gr.Tab(label="Trace IP packet route"):
        destination_ip = gr.Textbox(
            label="Destination IP Address",
            placeholder="Enter a destination IP to trace route.",
        )

        traceroute_results = gr.DataFrame(
            headers=["Country", "Region", "City", "Latitude", "Longitude", "Zip Code"],
        )

        traceroute_button = gr.Button("Traceroute")
        traceroute_button.click(
            traceroute, inputs=destination_ip, outputs=traceroute_results
        )

init_server(app=main)
