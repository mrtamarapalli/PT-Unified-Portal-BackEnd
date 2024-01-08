#createdBy:NagaTriveni Singareddy
"""Description :Fetching records from dynamodb table sidenav_masterdata and icon_master_data."""
# python version:3.11
#Modified On:10/10/2023

import boto3
import json
from customencoder import CustomEncoder
from datetime import datetime
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
## Table names in dynamodb
sidenav_masterdata_Table = 'sidenav_masterdata'
icon_masterdata_table = 'icon_masterdata'

## Initialize a Boto3 DynamoDB client
dynamodb = boto3.resource('dynamodb')
sidenav_table = dynamodb.Table(sidenav_masterdata_Table)
icon_masterdata_table = dynamodb.Table(icon_masterdata_table)
getMethod = 'GET'
healthPath = '/health'
sidenavpath = '/sidenavdetails'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path == healthPath:
        response = buildresponse(200)
    elif httpmethod == getMethod and path == sidenavpath:
        response = get_details()
    else:
        response = buildresponse(404, 'Not Found')
    return response
## Fetching details from dynamodb and generating jsonfile
def get_details():
    logger.info("entered sidenav_details_lambda  get_details method")
    try:
       sidenav_result=get_tabledata(sidenav_table)
       icon_result=get_tabledata(icon_masterdata_table)
       result=result_json(sidenav_result,icon_result)    
       body = {
            'sidenav_details': result
        }
       logger.info("ended sidenav_details_lambda  get_details method")
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
## Reading data from dynamodb
def get_tabledata(table):
    logger.info("entered sidenav_details_lambda  get_tabledata method")
    response = table.scan()
    result = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        result.extend(response['Items'])
    logger.info("ended sidenav_details_lambda  get_tabledata method")    
    return result        
## Method to create a service in json data      
def find_or_create_service(service_list, service_name,createdservice_name,icon_dict):
    for service in service_list:
        if service["name"] == service_name:
            return service
    new_service = {
        "name": service_name,
        "selected": False,
        createdservice_name: []
    }
    if service_name in icon_dict:
        new_service["icon"]=icon_dict[service_name]
    
    service_list.append(new_service)
    return new_service
## Creating a required format of json data for sidenav details  from the data that we are fetched from dynamodb
def result_json(sidenav_result,icon_result):
    data = []
    icon_dict={}
    for item in icon_result:
        icon_dict[item.get("name")]=item.get("icon")
    logger.info(icon_dict)
    for item in sidenav_result:
        parent = item.get("sidenav_parent")
        child = item.get("sidenav_child")
        subchild = item.get("sidnav_subchild")
        resource = item.get("resource")
        if parent:
            parent_service = find_or_create_service(data, parent,"children",icon_dict)
           
            if child:
                child_service = find_or_create_service(
                    parent_service["children"], child,"childrenServices",icon_dict)
                if subchild:
                    subchild_service = find_or_create_service(
                        child_service["childrenServices"], subchild,"services",icon_dict)
                    subchild_service["services"].append({"resource":resource,"icon":icon_dict[resource]})
            elif subchild:
                subchild_service = find_or_create_service(
                    parent_service["children"], subchild,"services",icon_dict)
                subchild_service["services"].append({"resource":resource,"icon":icon_dict[resource]})        
    return data        
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
    