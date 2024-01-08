# createdBy:NagaTriveni Singareddy
"""Description :Sending database types to read the data for particular database
"""
# python version:3.11
# Modified On:20/11/2023
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
dropdownpath = '/engine_details'


def lambda_handler(event: dict, context: LambdaContext) -> str:
    logger.info("entered engine_details_lambda lambda_handler")
    logger.info(event)
    httpMethod = event['httpMethod']
    path = event['path']
    if httpMethod == getMethod and path == dropdownpath:
        response = engine_details()
    else:
        logger.error("path or method not found")
        response = buildResponse(
            404, {"statusCode": 404, "response": "failed", "error": "path or method not found"})
    logger.info("ended engine_details_lambda lambda_handler")
    return response


def engine_details():
    try:
        logger.info("entered engine_details_lambda  engine_details method")
        engine_details = [{"engineType": "MYSQL",
                          "engine": ["mysql"]},
                          {"engineType": "MariaDB",
                           "engine": ["mariadb"]},
                          {"engineType": "PostgreSQL",
                           "engine": ["postgres"]},
                          {"engineType": "Oracle",
                           "engine": ["oracle-ee", "oracle-se2"]},
                          {"engineType": "Microsoft SQL Server",
                           "engine": ["sqlserver-ee", "sqlserver-se"]}]
        body = {
            "statusCode": 200,
            "response": "success",
            "engine_Details": engine_details
        }
        logger.info("ended engine_details_lambda  engine_details method")
        return buildResponse(200, body)
    except Exception as e:
        logger.error(e)
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
