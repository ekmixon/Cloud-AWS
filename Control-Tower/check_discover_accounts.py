
#  This script will call the Crowdstrike API to perform checks to ensure that the configured IAM role,
#  its associated permission, and external ID are set up correctly. '
#
#  This validates that the IAM role ARN and external ID provided for the account are configured '
#  and have all the required permissions in order for CrowdStrike to query the AWS API’s for your account.
#  Note that this does not currently validate access to the S3 bucket for CloudTrail logs.\n\n')

import argparse
import json
import logging
import sys
from logging.handlers import RotatingFileHandler

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
handler = RotatingFileHandler(
    "./get_registered_accounts.log", maxBytes=20971520, backupCount=5
)
formatter = logging.Formatter("%(levelname)-8s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def set_auth_header(auth_token: str) -> dict:
    """
    Creates the auth header for requests
    :param auth_token
    :return: dict
    """
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}",
    }


def check_account_access(auth_token: str, accounts: list) -> list:
    """
    Performs an Access Verification check on the specified AWS Account IDs


    :param auth_token:
    :param accounts:
    :return: dict:
    :example:

    Example check_account_access (token, ['12344667', '345678865'])
    """
    if accounts:
        params = []
        for account in accounts:
            params.append(f"ids={account}")
            param_string = "&".join(params)
    url = f"https://api.crowdstrike.com/cloud-connect-aws/entities/verify-account-access/v1?{param_string}"

    headers = set_auth_header(auth_token)
    logger.debug(f"url:{url}")
    logger.debug(f"headers:{json.dumps(headers, indent=2)}")
    try:
        r = requests.post(url, headers=headers)
        r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.debug(f"HTTP error {err} calling {url}")
        return
    except Exception as e:
        logger.debug("Failed to verify accounts")
        return
    r_content = json.loads(r.text)
    # accounts are listed in response[]
    return r_content["resources"]


def get_falcon_discover_accounts(sortby=None, filterby=None) -> bool:
    good_accounts = []
    bad_accounts = []

    url = "https://api.crowdstrike.com/cloud-connect-aws/combined/accounts/v1"
    PARAMS = {"limit": "100"}
    if filterby:
        PARAMS["filter"] = filterby
    if sortby:
        PARAMS["sort"] = sortby

    if auth_token := get_auth_token():
        auth_header = get_auth_header(auth_token)
    else:
        print("Failed to get auth token")
        sys.exit(1)
    headers = {
        "Content-Type": "application/json",
    }
    headers |= auth_header

    try:
        response = requests.request("GET", url, headers=headers, params=PARAMS)
        response_content = json.loads(response.text)
        logger.debug(f"Response to register = {response_content}")
        return response_content
    except Exception as e:
        logger.debug(f"Got exception {e}")
        return


def check_accounts():
    if response_content := get_falcon_discover_accounts():
        accounts_list = response_content["resources"]
        with open('accounts-status.json', 'w+') as f:
            json.dump(accounts_list, f)
        accounts_to_test = [account['id'] for account in accounts_list]
        auth_token = get_auth_token()
        if not auth_token:
            print("Failed to get auth token")
            sys.exit(1)
    else:
        error_code = response_content.status_code
        error_msg = response_content["errors"][0]["message"]
        logger.info(f"Got response error code {error_code} message {error_msg}")
        return


def get_auth_header(auth_token) -> str:
    if auth_token:
        auth_header = f"Bearer {auth_token}"
        return {"Authorization": auth_header}


def get_auth_token():
    url = "https://api.crowdstrike.com/oauth2/token"
    payload = f"client_secret={falcon_client_secret}&client_id={falcon_client_id}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.ok:
        response_object = response.json()
        if token := response_object.get("access_token", ""):
            return token
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get Params to send notification to CRWD topic"
    )

    parser.add_argument(
        "-f", "--falcon_client_id", help="Falcon Client ID", required=True
    )
    parser.add_argument(
        "-s", "--falcon_client_secret", help="Falcon Client Secret", required=True
    )
    args = parser.parse_args()
    falcon_client_id = args.falcon_client_id
    falcon_client_secret = args.falcon_client_secret
    check_accounts()
