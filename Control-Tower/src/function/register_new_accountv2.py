import json
import logging
import os
import random
import string
import sys
import time

# from botocore.vendored import requests
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SUCCESS = "SUCCESS"
FAILED = "FAILED"

cloudtrail_bucket_owner_id = os.environ['central_s3_bucket_account']
cloudtrail_bucket_region = os.environ['cloudtrail_bucket_region']
iam_role_arn = os.environ['iam_role_arn']
CSAccountNumber = os.environ['CSAccountNumber']
CSAssumingRoleName = os.environ['CSAssumingRoleName']
LocalAccount = os.environ['LocalAccount']
aws_region = os.environ['aws_region']
delay_timer = os.environ['delay_timer']
Falcon_Discover_Url = f'https://ctstagingireland.s3-{aws_region}.amazonaws.com/crowdstrike_role_creation_ss.yaml'


def delete_falcon_discover_account(payload, api_keys, api_method) -> bool:
    url = f'https://api.crowdstrike.com/cloud-connect-aws/entities/accounts/v1?ids={LocalAccount}'
    if auth_token := get_auth_token(api_keys):
        auth_header = get_auth_header(auth_token)
    else:
        print("Failed to auth token")
        sys.exit(1)
    headers = {
        'Content-Type': 'application/json',
    }
    headers |= auth_header
    try:
        response = requests.request("DELETE", url, headers=headers)
        if response.status_code == 200:
            print('Deleted account')
            return True
        else:
            print(
                f'Delete failed with response \n {response.status_code} \n{response["errors"][0]["message"]}'
            )

    except Exception as e:
        # logger.info('Got exception {} hiding host'.format(e))
        print(f'Got exception {e} hiding host')
        return


def register_falcon_discover_account(payload, api_keys, api_method) -> bool:
    cs_action = api_method
    url = "https://api.crowdstrike.com/cloud-connect-aws/entities/accounts/v1?mode=manual"
    if auth_token := get_auth_token(api_keys):
        auth_header = get_auth_header(auth_token)
    else:
        print("Failed to auth token")
        sys.exit(1)
    headers = {
        'Content-Type': 'application/json',
    }
    headers |= auth_header

    try:
        response = requests.request(cs_action, url, headers=headers, data=payload)
        response_content = json.loads(response.text)
        logger.info(f'Response to register = {response_content}')

        good_exit = 201 if cs_action == 'POST' else 200
        if response.status_code == good_exit:
            logger.info('Account Registered')
            return True
        elif response.status_code == 409:
            logger.info('Account already registered - nothing to do')
            return True
        else:
            error_code = response.status_code
            error_msg = response_content["errors"][0]["message"]
            logger.info('Account {} Registration Failed - Response {} {}'.format(error_code, error_msg))
            return
    except Exception as e:

        logger.info(f'Got exception {e}')
        return


def get_auth_header(auth_token) -> str:
    if auth_token:
        auth_header = f"Bearer {auth_token}"
        return {"Authorization": auth_header}


def get_auth_token(api_keys):
    FalconClientId = api_keys['FalconClientId']
    FalconSecret = api_keys['FalconSecret']
    url = "https://api.crowdstrike.com/oauth2/token"
    payload = f'client_secret={FalconSecret}&client_id={FalconClientId}'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.request('POST', url, headers=headers, data=payload)
    if response.ok:
        response_object = (response.json())
        if token := response_object.get('access_token', ''):
            return \
                token
    return


def format_notification_message(external_id, rate_limit_reqs=0, rate_limit_time=0):
    data = {
        "resources": [
            {
                "cloudtrail_bucket_owner_id": cloudtrail_bucket_owner_id,
                "cloudtrail_bucket_region": cloudtrail_bucket_region,
                "external_id": external_id,
                "iam_role_arn": iam_role_arn,
                "id": LocalAccount,
                "rate_limit_reqs": rate_limit_reqs,
                "rate_limit_time": rate_limit_time
            }
        ]
    }
    logger.info(f'Post Data {data}')
    return json.dumps(data)


def cfnresponse_send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']
    print(responseUrl)

    responseBody = {
        'Status': responseStatus,
        'Reason': f'See the details in CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': physicalResourceId or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
    }

    json_responseBody = json.dumps(responseBody)

    print("Response body:\n" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print(f"Status code: {response.reason}")
    except Exception as e:
        print(f"send(..) failed executing requests.put(..): {str(e)}")


def get_random_alphanum_string(stringLength=8):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for _ in range(stringLength))


def lambda_handler(event, context):
    try:
        response_data = {}
        logger.info(f'Event = {event}')
        if event['RequestType'] in ['Create']:
            api_keys = event['ResourceProperties']
            external_id = event['ResourceProperties']['ExternalID']
            # Format post message
            API_METHOD = 'POST'
            api_message = format_notification_message(external_id)
            # Register account
            try:
                delay = float(delay_timer)
            except Exception as e:
                logger.info(f'cant convert delay_timer type {type(delay_timer)} error {e}')
                delay = 60
            logger.info(f'Got ARN of Role Pausing for {delay} seconds for role setup')
            time.sleep(delay)
            register_result = register_falcon_discover_account(api_message, api_keys, API_METHOD)
            logger.info(f'Account registration result: {register_result}')
            if register_result:
                cfnresponse_send(event, context, SUCCESS, register_result, "CustomResourcePhysicalID")
            else:
                cfnresponse_send(event, context, FAILED, register_result, "CustomResourcePhysicalID")

        elif event['RequestType'] in ['Update']:
            logger.info('Event = ' + event['RequestType'])
            api_keys = event['ResourceProperties']
            external_id = event['ResourceProperties']['ExternalID']
            # Format post message
            API_METHOD = 'PATCH'
            api_message = format_notification_message(external_id)
            # Register account
            register_result = register_falcon_discover_account(api_message, api_keys, API_METHOD)
            logger.info(f'Account registration result: {register_result}')
            if register_result:
                cfnresponse_send(event, context, SUCCESS, "CustomResourcePhysicalID")
            else:
                cfnresponse_send(event, context, FAILED, "CustomResourcePhysicalID")

            logger.info('Event = ' + event['RequestType'])

            cfnresponse_send(event, context, 'SUCCESS', "CustomResourcePhysicalID")

        elif event['RequestType'] in ['Delete']:
            API_METHOD = 'DELETE'
            logger.info('Event = ' + event['RequestType'])
            api_keys = event['ResourceProperties']
            external_id = event['ResourceProperties']['ExternalID']
            api_message = format_notification_message(external_id)
            if result := delete_falcon_discover_account(
                api_message, api_keys, API_METHOD
            ):
                logger.info('Successfully deleted account in Falcon Discover portal')
            else:
                logger.info('Failed to delete account in Falcon Discover portal')
            response_data["Status"] = "Success"
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

    except Exception as e:
        logger.error(e)
        response_data = {}
        response_data["Status"] = str(e)
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
