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


def getAudits(token: str) -> Tuple[int, str]:
    scanURL = (
        # using type=container for testing, will allow for other types in the future
        tlUrl + "/api/v1/audits/incidents?limit=10&type=container&type=malware"
        if tlUrl is not None
        else exit(1)
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


def isFalsePostive(audit):
    # Define false positve values manually to easily add or remove flags that are flooding env
    falsePositiveNamespaces = ["default", "test-namespace"]
    falsePositiveCollections = ["dev", "test"]
    falsePositiveRegions = ["us-west-1", "eu-central-1"]
    # TODO figure out how to scope by rulename and use that as a data point
    # falsePositveTypes = ['container', 'function']
    # above example shows how we might extend scope beyond container
    falsePositveTypes = ["container"]
    # These will always raise alert and return false for isFalsePostive
    alertCategories = ["dataExfiltration", "malware", "lateralMovement"]
    # Check for categories that must always raise an alert

    if audit["category"] in alertCategories:
        return False
    for audit in audit["audits"]:
        if audit["hostname"] in alertCategories:
            return True
            # elif audit["rulename"] == "testRulename":
            return False
        elif audit["namespace"] in falsePositiveNamespaces:
            return False
        # k8s namespace
        # if audit["labels"].get("namespace") in falsePositiveNamespaces:
        return True
    # Using collections // This is to ensure functionality can persist even if original query is not fine tuned
    if falsePositiveCollections not in audit["collections"]:
        return False
    # If we want to ignore entire regions we can here
    if audit["region"] in falsePositiveRegions:
        return True
    if audit["type"] in falsePositveTypes:
        return True
    # If no false positve detections are made then we assume this is not a FP INC
    return False


def main():
    P: Tuple[str, str, str] = ("pcIdentity", "pcSecret", "tlUrl")
    accessKey, accessSecret, _ = map(checkParam, P)
    responseCode, cwpToken = (
        generateCwpToken(accessKey, accessSecret)
        if accessKey and accessSecret
        else (None, None)
    )

    responseCode, content = getAudits(cwpToken) if cwpToken else (exit(1))
    logging.info(content)
    audits = json.loads(content)
    logging.info(f"Number of audits found: {len(audits)}")
    logging.info(responseCode)
    print(isFalsePostive(audits[0]))


if __name__ == "__main__":
    main()
