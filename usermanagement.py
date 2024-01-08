#createdBy:NagaTriveni Singareddy
"""Description :Fetching records from dynamodb table based on values email_id,cloudprovider,resource.
based on the parameters we are fetching  list of operations that the user have permissions or not"""
# python version:3.11
#Modified On:11/10/2023

import boto3
from boto3.dynamodb.conditions import Key, Attr
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
#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
# Initilize the boto3 client
dynamodb = boto3.resource('dynamodb')
getMethod = 'GET'
usermanagementpath = '/usermanagement'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path ==usermanagementpath:
        response = resultant_records(event['queryStringParameters']['emailid'],event['queryStringParameters']['cloudprovider'],event['queryStringParameters']['resource'])
    else:
        response = buildResponse(404, 'Not Found')

    return response
def resultant_records(value,cloudprovider,resource):
    logger.info("entered usermanagement_lambda  resultant_records method")
    try:
        body = {
                    'usermanagementRecords':"data not found"
                }
                
        
        usermanagement_result=get_table_details('usermanagement',(Attr('email_id').eq(value))& (Attr('status').eq('active')))
        if(not  usermanagement_result):
           logger.info("usermanagement table is empty")
           return buildresponse(200, body) 
        roletable_result=get_table_details('roletable',(Attr('id').eq(usermanagement_result[0]['role_id']))& (Attr('status').eq('active')))
        if(not roletable_result):
           logger.info("roletable table is empty")
           return buildresponse(200, body) 
        
        operationsrole_mapping_table=get_table_details('operationsrole_mapping',(Attr('role_id').eq(usermanagement_result[0]['role_id']))& (Attr('status').eq('active')))
        if(not operationsrole_mapping_table):
            logger.info("operationsrole_mapping table is empty")
            return buildresponse(200, body) 
        operations_result=get_table_details('operations',((Attr('cloudprovider').eq(cloudprovider))&(Attr('resource').eq(resource)))& (Attr('status').eq('active')))
        if(not operations_result):  
            logger.info("operations table is empty")
            return buildresponse(200, body)   
        
        finalrecords_dict={'username':usermanagement_result[0]['email_id'],'rolename':roletable_result[0]['rolename']}
        operationid_value=[i['operation_id'] for i in operationsrole_mapping_table]
        operation_data_dict={}
        for value in operations_result:
            if value['id'] in operationid_value:
               operation_data_dict[value['operation']]=True
            else:
                operation_data_dict[value['operation']]=False     
        finalrecords_dict['operation'] = operation_data_dict 
        body = {
                'usermanagementRecords':finalrecords_dict
        }
        logger.info("ended usermanagement_lambda  resultant_records method")
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
def get_table_details(table,filterexpression):
    logger.info("entered usermanagement_lambda  get_table_details method")
    try:
        dynamodbtablename = table
        table = dynamodb.Table(dynamodbtablename)
        response = table.scan(
        
        FilterExpression=filterexpression)
             
        items = response.get('Items',[])
        logger.info("The {} records are {}".format(table,items))
        logger.info("entered usermanagement_lambda  get_table_details method")
        return items
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