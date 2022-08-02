import json
import logging
import os
import sys
import boto3
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONSTANTS
SUCCESS = "SUCCESS"
FAILED = "FAILED"


CSPM_ROLE_TEMPLATE_URL = 'https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com' \
                         '/aws_cspm_cloudformation_v1.1.json'
STACK_SET_NAME = "CrowdStrike-CSPM-Integration"


organizationalUnitId = os.environ['organizationalUnitId']
CSAccountNumber = os.environ['CSAccountNumber']
CSAssumingRoleName = os.environ['CSAssumingRoleName']
aws_region = os.environ['aws_region']


def deregister_falcon_horizon_account(account_id, api_keys, api_method) -> bool:
    cs_action = api_method
    url = f"https://api.crowdstrike.com/cloud-connect-cspm-aws/entities/account/v1?ids={account_id}"

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
        response = requests.request(cs_action, url, headers=headers)
        response_content = json.loads(response.text)
        logger.info(f'Response to deregister = {response_content}')
        good_exit = 201 if cs_action == 'POST' else 200
        if response.status_code == good_exit:
            logger.info('Account Deregistered')
            return True
        else:
            error_code = response.status_code
            logger.info(f'Account Deregistration Failed - Response {error_code}')
            return False
    except Exception as e:
        logger.info(f'Got exception {e}')


def register_falcon_horizon_account(payload, api_keys, api_method) -> dict:
    cs_action = api_method
    url = "https://api.crowdstrike.com/cloud-connect-cspm-aws/entities/account/v1"
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
        elif response.status_code == 409:
            logger.info('Account already registered - nothing to do')
        else:
            error_code = response.status_code
            error_msg = response_content["errors"][0]["message"]
            logger.info(f'Account Registration Failed - Response {error_code} {error_msg}')
        return response_content['resources'][0]
    except Exception as e:
        logger.info(f'Got exception {e}')


def get_auth_header(auth_token) -> dict:
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


def format_notification_message(account_id, organization_id):
    data = {
        "resources": [
            {
                "organization_id": organization_id,
                "account_id": account_id,
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


def lambda_handler(event, context):
    logger.info(f'Got event {event}')
    logger.info(f'Context {context}')
    try:
        response_data = {}
        logger.info(f'Event = {event}')
        CFT = boto3.client('cloudformation')
        api_keys = event['ResourceProperties']
        accountId = context.invoked_function_arn.split(":")[4]
        if event['RequestType'] in ['Create']:
            # Format post message
            API_METHOD = 'POST'
            api_message = format_notification_message(accountId, organizationalUnitId)
            register_result = register_falcon_horizon_account(api_message, api_keys, API_METHOD)
            logger.info(f'Account registration result: {register_result}')
            external_id = register_result['external_id']
            RoleName = register_result['iam_role_arn'].split('/')[-1]
            keyDict = {'ParameterKey': 'ExternalID', 'ParameterValue': external_id}
            CRWD_Discover_paramList = [dict(keyDict)]
            keyDict['ParameterKey'] = 'RoleName'
            keyDict['ParameterValue'] = RoleName
            CRWD_Discover_paramList.append(dict(keyDict))
            keyDict['ParameterKey'] = 'CSRoleName'
            keyDict['ParameterValue'] = CSAssumingRoleName
            CRWD_Discover_paramList.append(dict(keyDict))
            keyDict['ParameterKey'] = 'CSAccountNumber'
            keyDict['ParameterValue'] = CSAccountNumber
            CRWD_Discover_paramList.append(dict(keyDict))

            if cft_result := CFT.create_stack(
                StackName=STACK_SET_NAME,
                TemplateURL=CSPM_ROLE_TEMPLATE_URL,
                Parameters=CRWD_Discover_paramList,
                TimeoutInMinutes=5,
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                # RoleARN='string',
                Tags=[
                    {'Key': 'Vendor', 'Value': 'CrowdStrike'},
                ],
            ):
                logger.info(f"Created Stack {cft_result.get('StackId')}")
                cfnresponse_send(event, context, SUCCESS, register_result, "CustomResourcePhysicalID")
            else:
                cfnresponse_send(event, context, FAILED, register_result, "CustomResourcePhysicalID")

        elif event['RequestType'] in ['Update']:
            logger.info('Event = ' + event['RequestType'])
            cfnresponse_send(event, context, SUCCESS, "CustomResourcePhysicalID")

        elif event['RequestType'] in ['Delete']:
            logger.info('Event = ' + event['RequestType'])
            API_METHOD = 'DELETE'
            deregister_falcon_horizon_account(accountId, api_keys, API_METHOD)
            cft_result = CFT.delete_stack(
                StackName="CrowdStrike-CSPM-Integration")
            logger.info(f"Stack delete OperationId {cft_result.get('OperationId')}")
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

    except Exception as e:
        logger.info(f'Got exception {e}')
        response_data = {"Status": str(e)}
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
