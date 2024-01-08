#createdBy:NagaTriveni Singareddy
"""Description :Fetching records from dynamodb table accountdetails_masterdata """
# python version:3.11
#Modified On:11/10/2023

import boto3
import json
from customencoder import CustomEncoder
from botocore.exceptions import ClientError
from datetime import datetime
#import logging 
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
## Tablename
accountdetails_table= 'accountdetails_masterdata'

## Initialize a Boto3 DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(accountdetails_table)
getMethod = 'GET'
healthPath = '/health'
accountdetailspath = '/accountdetails'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path == healthPath:
        response = buildresponse(200)
    elif httpmethod == getMethod and path == accountdetailspath:
        response = get_accountdetails()
    else:
        response = buildresponse(404, 'Not Found')

    return response

## Fetching account details from accountdetails_masterdata in dynamodb table
def get_accountdetails():
    logger.info("entered account_details_lambda  get_accountdetails method")
    try:
        response = table.scan()
        result = response['Items']
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            result.extend(response['Items'])
        accountiddetails={'AccountId':result}
        body = {
            'accountdetails': accountiddetails
        }
        logger.info("ended account_details _lambda  get_accountdetails method")
        return buildresponse(200, body)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error("Table not found.")
            raise e
        elif e.response['Error']['Code'] == 'ProvisionedThroughputExceededException':
            logger.error("Provisioned throughput exceeded.")
            raise e
        else:
            logger.error(f"An error occurred: {e}")
            raise e
    except:
        logger.exception('Log it here for now')
def buildresponse(statuscode, body=None):
    response = {
        'statuscode': statuscode,
        'headers': {
            'ContentType': 'application/json',
            'Access-Control-Allow-Origin': '*'

            
        }
    }
    if body is not None:
        response['body'] = json.dumps(body, cls=CustomEncoder)
    return response