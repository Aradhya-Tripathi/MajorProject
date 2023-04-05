# This file is responsible for all threat assesments
# If the IP packets are classified as unsafe using anyof the classisfication
# APIs which have been called using the --threat-assesment option
# This class will be called passing all the information regarding the IP
# and the classification and will give the information based on it.


import os

from cli.renderer import console
from gpt import chat_session

BASE_URL = "https://api.openai.com/v1/chat/completions"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {os.getenv('chatapi')}",
}


def threat_assessment(
    ip_address: str, usage: str, is_safe: str, verbose: bool = True
) -> str:
    prompt = f"""I need your help to perform a threat analysis on an IP address.
I have already classified it as safe or unsafe using the AbuseIP API, and I have also determined its usage type.
Based on this information, I would like you to provide me with a threat score and any additional contextual information
that can help me determine the severity of the threat. Here are the details:

IP Address: {ip_address}
Usage Type: {usage}
Classification: {is_safe}

Please let me know the threat score and any additional contextual information
you can provide about this IP address. Thank you!
"""
    model = "gpt-3.5-turbo"
    messages = [
        {
            "role": "user",
            "content": prompt,
        },
    ]
    with console.status(
        status="[magenta]Loading threat assesments from chat gpt",
        verbose=verbose,
        spinner="earth",
    ):
        response = chat_session.post(
            url=BASE_URL, headers=HEADERS, json={"model": model, "messages": messages}
        )
    if response.ok:
        return response.json()["choices"][0]["message"]["content"]
