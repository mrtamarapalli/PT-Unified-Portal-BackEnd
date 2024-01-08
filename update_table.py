#createdBy:NagaTriveni Singareddy
"""Description :insterting or updating the records in instancetabledata_masterdata table based on the operation(insert,update) """
# python version:3.11
#Modified On:11/10/2023
import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
from customencoder import CustomEncoder
from datetime import datetime
#import logging 
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
instancetabledata = 'instancetabledata_masterdata'
# Inatilize boto3 client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(instancetabledata)

postMethod = 'POST'
update_tablepath = '/update_table'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == postMethod and path ==update_tablepath:
         if 'body' in event:
             try:
                 data = json.loads(event['body'])
                 logger.info(data)
                 if(data.get('operation')=="insert"):
                     response=insert_data(data)
                 else:
                     response=update_records(data)
            
             except json.JSONDecodeError as e:
                    body={
                        'errror_message': json.dumps({'error': 'Invalid JSON format'})}
                    return buildresponse(400, body)
         else:         
              response = buildresponse(404, ' data Not Found')
              return response
    else:
        response = buildresponse(404, 'Not Found')

    return response
# Inserting the record into dynamodb instancetabledata_masterdata
def insert_data(record):
    logger.info("entered update_table_lambda  insert_data method")
    del record['operation']
    try:
        response = table.get_item(Key={'uuid':record.get('uuid')})
        item = response.get('Item')

        if item:
            logger.info("The item with primary key exists in the table.")
            body = {
            'update':"record already present in dynamodb"
             }
        else:
             response = table.put_item(Item=record)
             logger.info("Item inserted successfully!")
             body = {
            'update':"record inserted sucessfully"
        }
        logger.info("ended update_table_lambda  insert_data method") 
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
    except Exception as e:
          logger.exception(f"Error inserting item: {e}")
 # updating the record in dynamodb instancetabledata_masterdata           
def update_records(record):
    try:
        logger.info("entered update_table_lambda  update_records method")
        del record['operation']
        response = table.update_item(
            Key={"uuid":record.get('uuid')},
            UpdateExpression='SET #attr1 = :val1,#attr2 = :val2',
            ExpressionAttributeNames={'#attr1': "status",'#attr2': "comment"},
            ExpressionAttributeValues={
                ":val1": record.get('status'),
                ":val2": record.get('comment')
            }
            
        )
        logger.info("records updated sucessfully")
        body = {
                'update':"record updated sucessfully"
                }
        logger.info("ended update_table_lambda  update_records method")
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
    except Exception as e:
          logger.exception(f"Error updating item: {e}")         
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