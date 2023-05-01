import os

from cli.renderer import console
from gpt import chat_session

if os.getenv("chatapi").strip().lower() == "none":
    raise Exception("You need to add your chat-gpt api key to access this!")

BASE_URL = "https://api.openai.com/v1/chat/completions"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {os.getenv('chatapi')}",
}
MAX_TOKENS = 150


def send_request(data) -> None | dict[str, str]:
    data.update({"max_tokens": MAX_TOKENS})
    response = chat_session.post(url=BASE_URL, headers=HEADERS, json=data)
    if response.ok:
        return response.json()["choices"][0]["message"]["content"]

    raise ConnectionError(f"Issue with chat gpt: {response.json()}")


def get_data(prompt: str, model: str = "gpt-3.5-turbo") -> dict[str, str | list]:
    return {"model": model, "messages": [{"role": "user", "content": prompt}]}


def single_ip_address(
    ip_address: str, usage: str, is_safe: str, verbose: bool = True
) -> str:
    prompt = f"""I need your help to perform a threat analysis on an IP address.
I have already classified it as safe or unsafe using the AbuseIP API, and I have also determined its usage type.
Based on this information, I would like you to provide me with a threat score and any additional contextual information
that can help me determine the severity of the threat. Here are the details:

IP Address: {ip_address}
Usage Type: {usage}
Classification: {is_safe}

Please let me know more about this IP address, and please response in a well formatted way.
Please be brief.
"""
    data = get_data(prompt=prompt)
    with console.status(
        status="[magenta]Loading threat assesments from chat gpt",
        verbose=verbose,
        spinner="bouncingBall",
    ):
        return send_request(data=data)


def port_usages(ports: list[str], verbose: bool = False) -> str:
    prompt = f"""I need your help in elaborating on the usages of the following ports:
    {" ".join(ports)}
"""
    data = get_data(prompt=prompt)

    with console.status(
        status="[magenta]Loading port usages from chat gpt",
        verbose=verbose,
        spinner="bouncingBall",
    ):
        return send_request(data=data)


def intermediate_nodes(ip_addresses: list[str], verbose: bool = False) -> str:
    prompt = f"""I need your help in finding out information about the following IP addresses:
     {", ".join(ip_addresses)}
"""
    data = get_data(prompt=prompt)

    with console.status(
        status="[magenta]Loading details about the IP addresses from chat gpt",
        verbose=verbose,
        spinner="bouncingBall",
    ):
        return send_request(data=data)
