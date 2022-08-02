import json
import logging

import boto3
import requests

# Set up our logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

SUCCESS = "SUCCESS"
FAILED = "FAILED"


def cfnresponse_send(event, context, responseStatus, physicalResourceId=None, noEcho=False):
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
    try:
        response_data = {}
        if event['RequestType'] in ['Create']:
            event_data = event['ResourceProperties']
            log_archive_acct = event_data['log_archive_acct']
            region = event_data['region']
            bucket = event_data['log_archive_bucket']
            crwd_topic_arn = event_data['crwd_topic_arn']

            s3 = boto3.resource('s3')
            bucket_notification = s3.BucketNotification(bucket)
            print(bucket_notification)

            response = bucket_notification.put(
                NotificationConfiguration={
                    'TopicConfigurations': [
                        {
                            'Id': 'string',
                            'TopicArn': crwd_topic_arn,
                            'Events': ['s3:ObjectCreated:Put'
                                       ],
                        },
                    ]})
            logger.info(f'Response to bucket notification add {response}')
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                cfnresponse_send(event, context, SUCCESS, "CustomResourcePhysicalID")
            else:
                cfnresponse_send(event, context, FAILED, "CustomResourcePhysicalID")
        else:
            cfnresponse_send(event, context, SUCCESS, "CustomResourcePhysicalID")
    except Exception as e:
        logger.info(f'Got exception {e}')
        cfnresponse_send(event, context, FAILED, "CustomResourcePhysicalID")
    return "Created notification"
