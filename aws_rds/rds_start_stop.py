import boto3
import json
from datetime import datetime
import botocore
from botocore.exceptions import ClientError,ParamValidationError,NoCredentialsError,EndpointConnectionError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
getMethod = 'GET'
dropdownpath = '/start_stop_reboot_rds'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info("entered engine_details_lambda lambda_handler")
    logger.info(event)
    httpMethod = event['httpMethod']
    path = event['path']
    parameter=event['queryStringParameters']
    if httpMethod == getMethod and path ==dropdownpath:
        response = instanceidentifier_action(parameter['param1'],parameter['param2'],parameter['param3'])
    else:
        logger.error("path or method not found")
        response = buildResponse(404, {"statusCode":404,"response":"failed","error":"path or method not found"})
    logger.info("ended engine_details_lambda lambda_handler")
    return response
def instanceidentifier_action(accountid,db_instance_identifier,action):
    try:
        rds = boto3.client('rds')
        # Start RDS instance
        response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
        db_instance_status = response['DBInstances'][0]['DBInstanceStatus']
        logger.info(db_instance_status)
        
        if (action.lower()=='start') and (db_instance_status=='stopped'):
            rds.start_db_instance(DBInstanceIdentifier=db_instance_identifier)
            logger.info(f"Started RDS instance {db_instance_identifier}")
            status=f"Start operation RDS instance {db_instance_identifier} sucessfully.please check the status after sometime"
        # Stop RDS instance
        elif (action.lower()=='stop') and (db_instance_status=='available'):
            rds.stop_db_instance(DBInstanceIdentifier=db_instance_identifier)
            logger.info(f"Stopped RDS instance {db_instance_identifier}")
            status=f"Stop operation RDS instance {db_instance_identifier} sucessfully."
        # Reboot RDS instance
        elif (action.lower()=='reboot') and (db_instance_status=='available'):
            # Reboot RDS instance
            rds.reboot_db_instance(DBInstanceIdentifier=db_instance_identifier)
            logger.info(f"Rebooted RDS instance {db_instance_identifier}")
            status=f"Reboot operation RDS instance {db_instance_identifier} sucessfully.please check the status after sometime"
        else:
            status=f"Invalid operation {action}.RDS instance {db_instance_identifier} is in {db_instance_status} state"
            body = {
                 "statusCode": 400,
                 "response":"failed",
                 "identifier_Status": status
            }
            return buildResponse(400,body)     
            
        body = {
                 "statusCode": 200,
                 "response":"success",
                 "identifier_Status": status
            }
        return buildResponse(200,body)     
    except Exception as e:
        logger.info(e)
        return buildResponse(400, {"statusCode":400,"response":"failed","error":str(e)}) 
        
def buildResponse(statusCode, body=None):
    response = {
        'statusCode': statusCode,
        'headers': {
            'ContentType': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body)
    return response        