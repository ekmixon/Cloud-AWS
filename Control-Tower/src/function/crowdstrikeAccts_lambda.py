import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

stackset_list = ['CrowdstrikeDiscover-IAM-ROLES']
result = {"ResponseMetadata": {"HTTPStatusCode": "400"}}


def lambda_handler(event, context):
    masterAcct = event['account']
    eventDetails = event['detail']
    regionName = eventDetails['awsRegion']
    eventName = eventDetails['eventName']
    srvEventDetails = eventDetails['serviceEventDetails']
    if eventName == 'CreateManagedAccount':
        newAccInfo = srvEventDetails['createManagedAccountStatus']
        cmdStatus = newAccInfo['state']
        if cmdStatus == 'SUCCEEDED':
            '''Sucessful event recieved'''
            ouInfo = newAccInfo['organizationalUnit']
            ouName = ouInfo['organizationalUnitName']
            odId = ouInfo['organizationalUnitId']
            accId = newAccInfo['account']['accountId']
            accName = newAccInfo['account']['accountName']
            CFT = boto3.client('cloudformation')

            for item in stackset_list:
                try:
                    result = CFT.create_stack_instances(StackSetName=item, Accounts=[accId], Regions=[regionName])
                    logger.info(f'Processed {item} Sucessfully')

                except Exception as e:
                    logger.error(f'Unable to launch in:{item}, REASON: {e}')
        else:
            '''Unsucessful event recieved'''
            logger.info(f'Unsucessful Event Recieved. SKIPPING :{event}')
            return (False)
    else:
        logger.info(f'Control Tower Event Captured :{event}')
