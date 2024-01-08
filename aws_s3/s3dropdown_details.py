# createdBy:NagaTriveni Singareddy
"""Description :Fetching AWS s3 bucket details for a particular account using boto3 apis
"""
# python version:3.11
# Modified On:15/11/2023

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
dropdownpath = '/s3_dropdown_details'


def lambda_handler(event: dict, context: LambdaContext) -> str:
    logger.info("entered dropdown_details_lambda lambda_handler")
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    parameters = event['queryStringParameters']
    for i, j in parameters.items():
        print(i)
        if j.lower() not in ["aws", "s3"] and i != 'param3':
            logger.error(f"invaild value {i}")
            return buildResponse(400, {"statusCode": 400, "response": "failed", "error": f"invaild value {i}"})
            break
    if httpmethod == getMethod and path == dropdownpath:
        response = get_dropdown_details(parameters['param3'])
    else:
        logger.error("path or method not found")
        response = buildresponse(
            404, {"statusCode": 404, "response": "failed", "error": "path or method not found"})
    logger.info("ended dropdown_details_lambda lambda_handler")
    return response


def kms_value():
    try:
        logger.info("entered dropdown_details_lambda kms_value method")
        kms_client = boto3.client('kms')
        kmskey_response = kms_client.list_aliases()
        logger.info(kmskey_response)
        kms_result = [{'value': value['AliasArn'], 'label': value['AliasArn']}
                      for value in kmsresponse['Alias'][0]]
        logger.info("ended dropdown_details_lambda kms_value method")
        return kms_result
    except Exception as e:
        logger.error(e)


def get_enabled_s3_regions():
    # Use botocore to get all AWS regions
    logger.info("entered dropdown_details_lambda  get_enabled_s3_regions")
    session = boto3.session.Session()
    available_regions = session.get_available_regions('s3')

    # # Check if S3 is available in each region
    enabled_s3_regions = [{'label': region, 'value': region}
                          for region in available_regions if is_s3_enabled(region)]
    logger.info(enabled_s3_regions)
    logger.info("ended dropdown_details_lambda get_enabled_s3_regions")
    return enabled_s3_regions


def is_s3_enabled(region):
    try:
        # Attempt to create an S3 client for the region
        logger.info("entered dropdown_details_lambda  is_s3_enabled method")
        s3 = boto3.client('s3', region_name=region)
        s3.list_buckets()  # Try listing buckets to check if S3 is accessible
        logger.info("ended dropdown_details_lambda  is_s3_enabled method")
        # If listing buckets succeeds, assume S3 is enabled in the region
        return True
    except botocore.exceptions.NoCredentialsError:
        logger.error(f"Skipping region {region} due to lack of credentials.")
    except botocore.exceptions.EndpointConnectionError:
        logger.error(f"S3 is not enabled in region {region}.")
    except Exception as e:
        # print(str(e))
        logger.error(f"invalid token  in region {region}.")
    return False


def get_dropdown_details(accountid):
    try:
        logger.info(
            "entered s3_dropdown_details_lambda  get_dropdown_details method")
        dropdown_details = {'accountId': accountid,
                            'region': get_enabled_s3_regions(), 'kmskeyid': kms_value()}
        logger.info(dropdown_details)
        body = {
            "statusCode": 200,
            "response": "success",
            "s3_dropdown_Details": dropdown_details

        }
        logger.info(
            "ended dropdown_details_lambda  get_dropdown_details method")
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
