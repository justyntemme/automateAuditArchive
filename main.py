import json
import logging
import os
from typing import Tuple

import requests

logging.basicConfig(level=logging.INFO)


# Global Variables
n = None  # To shorten line lengths
tlUrl = os.environ.get("tlUrl")
pcUrl = os.environ.get("pcUrl")


def getScans(token: str) -> Tuple[int, str]:
    scanURL = (
        tlUrl + "/api/v1/audits/runtime/container" if tlUrl is not None else exit(1)
    )
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    response = requests.get(scanURL, headers=headers, timeout=60, verify=False)
    return (response.status_code, response.text)


def generateCwpToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = f"{tlUrl}/api/v1/authenticate" if tlUrl is not n else exit(1)

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        authURL, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.error(
            "Unable to acquire token with error code: %s", response.status_code
        )

    return response.status_code, ""


def checkParam(paramName: str) -> str:
    paramValue = os.environ.get(paramName)
    if paramValue is None:
        logging.error(f"Missing {paramName}")
        raise ValueError(f"Missing {paramName}")
    return paramValue


def main():
    P: Tuple[str, str, str] = ("pcIdentity", "pcSecret", "tlUrl")
    accessKey, accessSecret, _ = map(checkParam, P)
    responseCode, cwpToken = (
        generateCwpToken(accessKey, accessSecret)
        if accessKey and accessSecret
        else (None, None)
    )

    responseCode, content = getScans(cwpToken) if cwpToken else (exit(1))
    logging.info(responseCode)
    logging.info(content)


if __name__ == "__main__":
    main()
