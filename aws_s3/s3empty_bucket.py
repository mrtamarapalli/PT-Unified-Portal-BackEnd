# createdBy:NagaTriveni Singareddy
"""Description :Fetching objects from s3 bucket and deleting the objects to empty the bucket for a particular account using boto3 apis
"""
# python version:3.11
# Modified On:16/11/2023
from aws_xray_sdk.core import patch_all
from aws_xray_sdk.core import xray_recorder
import boto3
import json
from datetime import datetime
import botocore
from botocore.exceptions import ClientError, ParamValidationError, NoCredentialsError, EndpointConnectionError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
patch_all()
getMethod = 'GET'
dropdownpath = '/empty_bucket'


def lambda_handler(event: dict, context: LambdaContext) -> str:
    logger.info("entered empty_bucket_lambda lambda_handler")
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    parameters = event['queryStringParameters']
    if httpmethod == getMethod and path == dropdownpath:
        response = empty_bucket(parameters['param1'], parameters['param2'])
    else:
        logger.error("path or method not found")
        response = buildResponse(
            404, {"statusCode": 404, "response": "failed", "error": "path or method not found"})
    logger.info("ended empty_bucket_lambda lambda_handler")
    return response


def empty_bucket(accountid, bucket_name):
    try:
        logger.info("entered empty_bucket_lambda empty_bucket method")
        # List all objects in the bucket
        s3 = boto3.client('s3')
        response = s3.list_objects_v2(Bucket=bucket_name)

        if 'Contents' in response:
            # Delete all objects in the bucket
            for obj in response['Contents']:
                s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
            logger.info(
                f"All objects in '{bucket_name}' deleted successfully.")
            body = {"statusCode": 200,
                    "response": "success",
                    "message": f"All objects in '{bucket_name}' deleted successfully"
                    }
            logger.info("ended empty_bucket_lambda empty_bucket method")
            return buildResponse(200, body)
        else:
            logger.info(
                f"No objects found in '{bucket_name}'. Bucket is already empty.")
            body = {"statusCode": 200,
                    "response": "success",
                    "message": f"No objects found in '{bucket_name}'. Bucket is already empty"
                    }
            logger.info("ended empty_bucket_lambda empty_bucket method")
            return buildResponse(200, body)
    except Exception as e:
        logger.error(f"Error emptying bucket: {e}")
        return buildResponse(400, {"statusCode": 400, "response": "failed", "error": str(e)})


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
