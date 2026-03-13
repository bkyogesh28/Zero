import requests

URL = "http://192.168.135.130:8000/telemetry"


def send_event(event: dict) -> None:
    try:
        response = requests.post(URL, json=event, timeout=10)
        print("Status:", response.status_code)

        try:
            print("Response:", response.json())
        except ValueError:
            print("Response:", response.text)

    except requests.exceptions.RequestException as e:
        print("Failed to send telemetry:", e)