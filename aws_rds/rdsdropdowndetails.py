#createdBy:NagaTriveni Singareddy
"""Description :Fetching rds databasedetails for a particular account using boto3 apis
"""
# python version:3.11
#Modified On:20/11/2023

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
dropdownpath = '/dropdown_details'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info("entered dropdown_details_lambda lambda_handler")
    logger.info(event)
    httpMethod = event['httpMethod']
    path = event['path']
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    parameters=event['queryStringParameters']
    for i,j in parameters.items():
        print(i)
        if j.lower() not  in ["aws","rds"]and i not in ['param3','param4']:
          logger.error(f"invaild value {i}")    
          return buildResponse(400, {"statusCode":400,"response":"failed","error":f"invaild value {i}"})
          break
        if httpMethod == getMethod and path ==dropdownpath:
           response = Get_Dropdown_Details(param3,param4)
        else:
            logger.error("path or method not found")
            response = buildresponse(404, {"statusCode":404,"response":"failed","error":"path or method not found"})
    logger.info("ended dropdown_details_lambda lambda_handler")

    return response
def rds_values(response):
    result = []
    logger.info("entered rds_dropdown_details_lambda rds_values method")
    for value in response[0][response[1]]:
        if (value.get(response[2]) not in [i['value'] for i in result]):
            result.append({'value': value.get(response[2]),
                           'label': value.get(response[3])})
    logger.info("ended s3_dropdown_details_lambda rds_values method")
    return result    

def Get_Dropdown_Details(accountid,enginetype):
    try:
        logger.info("entered s3_dropdown_details_lambda  Get_Dropdown_Details method")
        rds_client = boto3.client('rds', 'us-east-1',
                          aws_access_key_id='AKIAYH4L7KJ7VIMZ57HT',
                          aws_secret_access_key='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')
        # option_group_response = rds_client.describe_option_group_options(
        # EngineName=enginetype)
        #response = rds_client.describe_db_parameter_groups()
        # print(response)
        engine_version_response = rds_client.describe_db_engine_versions(
            Engine=enginetype)
        # instance_class_response = rds_client.describe_reserved_db_instances_offerings(
        #     ProductDescription=enginetype)
        securitygroup_response = rds_client.describe_db_security_groups()
        # print(instance_class_response)
        subnetgroup_response = rds_client.describe_db_subnet_groups()
        kms_client=boto3.client('kms', 'us-east-1',
                          aws_access_key_id='AKIAYH4L7KJ7VIMZ57HT',
                          aws_secret_access_key='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')
        kmskey_response =kms_client.list_aliases()
        rds_dropdown_input = {'dbEngineVersion': [
            engine_version_response, 'DBEngineVersions', 'EngineVersion', 'EngineVersion'],
            'parameterGroup': [engine_version_response, 'DBEngineVersions', 'DBParameterGroupFamily', 'DBParameterGroupFamily'],
            'majorEngineVersion': [engine_version_response, 'DBEngineVersions', 'MajorEngineVersion', 'MajorEngineVersion'],
            'subnetgroupname': [subnetgroup_response, 'DBSubnetGroups', 'DBSubnetGroupName', 'VpcId'], 'securityGroupName': [securitygroup_response, 'DBSecurityGroups', 'DBSecurityGroupName', 'DBSecurityGroupName'],
            "kms_key_id": [kmskey_response, 'Aliases', 'AliasArn', 'AliasArn'],'performance_insights_kms_key_id': [kmskey_response, 'Aliases', 'AliasArn', 'AliasArn']
        }
        
        # print(engine_version_response)

        rds_dropdown_output = {}
        for key, value in rds_dropdown_input.items():
            rds_dropdown_output[key] = rds_values(value)
        logger.info(engine_version_response)
        body = {
        "statusCode": 200,
        "response":"success",
        "dropdown_Details": rds_dropdown_output
        }
        logger.info("ended dropdown_details_lambda Get_Dropdown_Details")    
        return buildResponse(200, body)
    except ClientError as e:
        logger.error(e)
        return buildResponse(400, {"statusCode":400,"response":"failed","error":str(e)})  
    except Exception as e:
        logger.error(e)
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