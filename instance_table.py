#createdBy:NagaTriveni Singareddy
"""Description :Fetching records from dynamodb table instancetabledata_masterdata based on values accountid,cloudprovider,resource."""
# python version:3.11
#Modified On:10/10/2023

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
from customencoder import CustomEncoder
from secret_key import get_secret
from datetime import datetime
#import logging 
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
#logger = logging.getLogger()
#logger.setLevel(logging.INFO)

#dynamodb table
instancetabledata_table = 'instancetabledata_masterdata'
# Inatilize boto3
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(instancetabledata_table)
getMethod = 'GET'
instancetablepath = '/instance_table'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path ==instancetablepath:
        response = get_instance_details(event['queryStringParameters']['accountid'],event['queryStringParameters']['platform'],event['queryStringParameters']['requestedinstance'])
    else:
        response = buildresponse(404, 'Not Found')

    return response
#fetchig data from dynamodb
def get_instance_details(accountidvalue,platformvalue,requested_instance_value):
    logger.info("entered instance_table_lambda  get_instance_details method")
    try:
    
        response = table.scan(
        
         FilterExpression=Attr('accountId').eq(accountidvalue.upper())&Attr('platform').eq(platformvalue.upper())&Attr('requestedInstance').eq(requestedInstancevalue.upper())
         )

        items = response.get('Items',[])
        if(requested_instance_value.lower()=='ec2'):
            result=statusvalues(items,accountidvalue)
            items=result
        
        body = {
            'instanceRecords': items
        }
        logger.info("ended instance_details_lambda  get_instance_details method")
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
    except:
        logger.exception('Log it here for now')
def statusvalues(items,accountid_value):
    secret_value=json.loads(get_secret(accountid_value))
    ec2_client = boto3.client('ec2',
                           'us-east-1',
                           aws_access_key_id= secret_value['aws_access_key_id'],
                           aws_secret_access_key=secret_value['aws_secret_access_key'])
    for value in items:
        logger.info(value.get('instanceID'))
        
        response= ec2_client.describe_instance_status(InstanceIds=[i.get('instanceID')],IncludeAllInstances=True)
        value['InstanceState']=response['InstanceStatuses'][0]['InstanceState']['Name']
        value['InstanceStatus']=response['InstanceStatuses'][0]['InstanceStatus']['Status']
        value['SystemStatus']=response['InstanceStatuses'][0]['SystemStatus']['Status']

    return items                   
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