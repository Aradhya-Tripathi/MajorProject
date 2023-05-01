import joblib
import numpy
from scapy import all as modules

from cli.renderer import console


def load_prerequisits(
    model_path: str = "src/ip/model/model.joblib",
    scaler_path: str = "src/ip/model/scaler.joblib",
):
    return joblib.load(model_path), joblib.load(scaler_path)


with console.status("Loading the model and transformer...", spinner="earth"):
    MODEL, SCALER = load_prerequisits()

PROTOCAL_MAP = {"icmp": 0, "tcp": 1, "udp": 2}
FLAG_MAP = {
    "SF": 0,
    "S0": 1,
    "REJ": 2,
    "RSTR": 3,
    "RSTO": 4,
    "SH": 5,
    "S1": 6,
    "S2": 7,
    "RSTOS0": 8,
    "S3": 9,
    "OTH": 10,
}


def preproc(packets: list[modules.Packet]) -> list:
    if not packets:
        return

    for packet in packets:
        flag = str(packet[1])
        protocal = str(packet[0]).lower()
        packet[1] = FLAG_MAP[flag] if flag in FLAG_MAP else 10
        packet[0] = PROTOCAL_MAP[protocal] if protocal in PROTOCAL_MAP else 3

    return SCALER.transform(packets)


def predict(packets: list[modules.Packet]) -> float:
    processed_packet = preproc(packets=packets)

    try:
        if type(processed_packet) == numpy.ndarray:
            return MODEL.predict(processed_packet)
    except Exception as e:
        return None
