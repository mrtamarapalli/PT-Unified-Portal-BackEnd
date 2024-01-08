# createdBy:NagaTriveni Singareddy
"""Description :Fetching AWS s3 bucket details for a particular account using boto3 apis to edit the bucket
"""
# python version:3.11
#Modified On:17/11/2023
import boto3
import json
from customencoder import CustomEncoder
from datetime import datetime
from reading_s3bucket_files.py import file_reading
import botocore
from botocore.exceptions import ClientError,ParamValidationError,NoCredentialsError,EndpointConnectionError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
getMethod = 'GET'
dropdownpath = '/bucketedit_details'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    logger.info("entered dropdown_details_lambda  lambda_handler")
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path ==dropdownpath:
        response = final_instance_details(event['queryStringParameters']['accountid'],event['queryStringParameters']['instanceid'],event['queryStringParameters']['uuid'])
    else:
        response = buildresponse(404, 'Not Found')
    logger.info("ended dropdown_details_lambda  lambda_handler")
    return response
def instance_tags(instancetags):
    tags_dict = {}
    for tag in instancetags:

        tags_dict[tag['Key']] = tag['Value']
    return tags_dict

def resource_parameter_fields(accountid,bucketname,event_json_result):
    logger.info("entered dropdown_details_lambda  resource_parameter_fields methods")
    s3_client=boto3.client('s3')
    resourceparamter_fields = {}
    response_access=s3_client.get_public_access_block(Bucket=bucketname)
    print(response_access['PublicAccessBlockConfiguration'])
    response_logging=s3_client.get_bucket_logging(Bucket=bucketname)
    print(response_logging)
    response_tagging=s3_client.get_bucket_tagging(Bucket=bucketname)
    print(response_tagging['TagSet'])
    response_controls=s3_client.get_bucket_ownership_controls(Bucket=bucketname)
    print(response_controls['OwnershipControls'])
    response_encryption=s3_client.get_bucket_encryption(Bucket=bucketname)
    print(response_encryption['ServerSideEncryptionConfiguration'])
    resourceparamter_fields["block_public_acls"]=response_access['PublicAccessBlockConfiguration']['BlockPublicAcls']
    resourceparamter_fields["block_public_policy"]=response_access['PublicAccessBlockConfiguration']['BlockPublicPolicy']
    resourceparamter_fields["bucket"]=bucketname
    #hardcoded value configstatus
    resourceparamter_fields["config_status"]="Enabled"
    resourceparamter_fields["ignore_public_acls"]= response_access['PublicAccessBlockConfiguration']['IgnorePublicAcls']
    sse_algorithm=response_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
    if(sse_alogrithm=='aws:kms'):
       resourceparamter_fields["kms_master_key_id"]=response_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
    else:
        resourceparamter_fields["kms_master_key_id"]=event_json_result['requests'][0]['resourceparamter']['kms_master_key_id']
    #hardcoded value kms_master_key_usage
    resourceparamter_fields["kms_master_key_usage"]: True
    resourceparamter_fields["log_bucket_name"]=response_logging[ 'LoggingEnabled']['TargetBucket']
    resourceparamter_fields["object_ownership"]=response_controls['OwnershipControls']['Rules'][0]['ObjectOwnership']
    #hardcoded value policy_create_check
    resourceparamter_fields["policy_create_check"]=True
    resourceparamter_fields["restrict_public_buckets"]=response_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
    resourceparamter_fields["sse_algorithm_1"]=response_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
    resourceparamter_fields["tags"]=instance_tags(response_tagging['TagSet'])
    logger.info("ended dropdown_details_lambda  resource_parameter_fields methods")
    return resourceparamter_fields
result=resource_parameter_fields('accountid','gen-mohammadbucket','event_json_result')   
print(result) 
def request_fields(accountid,bucketname,event_json_result,uuid):
    logger.info("entered dropdown_details_lambda  request_fields method")
    requests = []
    request_dict = {}
    request_dict["seqnumber"]: uuid.split("-")[2]
    request_dict["env"] = event_json_result[requests][0]["env"]
    request_dict["platform"] = event_json_result[requests][0]["platform"]
    s3_client=bot3.client('s3')
    response_region=s3_client.get_bucket_location(Bucket=bucketname)
    request_dict["region"]=response_region['LocationConstraint']
    request_dict["accountid"] = response['Reservations'][0]['OwnerId']
    request_dict["action"] = event_json_result[requests][0]["deploy"]
    request_dict["resourcetype"] = event_json_result[requests][0]["resourcetype"]
    request_dict["cibuildid"] = event_json_result[requests][0]["cibuildid"]
    request_dict["prid"]: event_json_result[requests][0]["prid"]
    request_dict["uuid"]: uuid
    request_dict["resourceparamter"] = resource_parameter_fields(
        accountid,bucketname, event_json_result)
    request_dict["jsonfiles"] = event_json_result['requests'][0]["jsonfiles"]    
    requests.append(request_dict)
    logger.info("ended dropdown_details_lambda  request_fields method")
    return requests
def dropdown_result_values(value):
    
    dropdown_result_list=[]
    if isinstance(value,list):
        for i in value:
            dropdown_result_list.append({'value':i,'lable':i})
        return dropdown_result_list    
    else:
        return  {'value':value,'lable':value}     

def get_table_details(accountid):
    logger.info("entered dropdown_details_lambda  get_table_details method")
    accountdetails_table= 'accountdetails_masterdata'
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(accountdetails_table)
    logger.info("entered usermanagement_lambda  get_table_details method")
    dynamodbtablename = table
    table = dynamodb.Table(dynamodbtablename)
    response = table.scan(
    FilterExpression=Attr('accountid').eq(accountid))
    items = response.get('Items',[])
    logger.info("ended dropdown_details_lambda  get_table_details method")
    return items
def dropdown_details(accountid,bucketname,uuid,event_json_result):
    logger.info("entered dropdown_details_lambda  dropdown_details method")
    dropdown_details_dict={}
    dropdown_details_dict["subnetId"]=subnetname(response)
    resource_parameter_result=resource_parameter_fields(accountid,bucketname,event_json_result)
    requests_field_result=request_fields(accountid,bucketname,event_json_result,uuid)
    dropdown_details_dict["accountId"]=get_table_details(accountid)
    dropdown_details_dict["region"]=dropdown_result_values( requests_field_result['region'])
    dropdown_details_dict["kmskeyid"]=dropdown_result_values(resource_parameter_result["kms_master_key_id"])
    logger.info("ended dropdown_details_lambda  dropdown_details method")
    return dropdown_details_dict

def final_bucket_details(accountid,bucketname,uuid):
    logger.info("entered dropdown_details_lambda  final_bucket_details method")
    try:
        event_json_result = json.loads(file_reading(uuid))

        final_bucket_details_dict = {}
        final_bucket_details_dict["apiversion"] = event_json_result["apiversion"]
        final_bucket_details_dict["ticketid"] = uuid.split("-")[0]
        final_bucket_details_dict["projectid"] = uuid.split("-")[1]
        final_bucket_details_dict["changeticketid"] = uuid.split("-")[0]
        final_bucket_details_dict["description"] = event_json_result["description"]
        final_bucket_details_dict["attemptid"] = uuid.split("-")[-1]
        final_bucket_details_dict["gitorgname"] = event_json_result["gitorgname"]
        final_bucket_details_dict["requests"] = request_fields(accountid,bucketname,
                                                                event_json_result,uuid)
        final_instance_details_dict['dropdown_details']=dropdown_details(accountid,bucketname,uuid,event_json_result)
        body = {
            'statuscode':200,
            'response':"sucess",
            's3EditDetails': final_bucket_details_dict
        }
        logger.info("ended single_instance_details_lambda   final_instance_details method")
        return buildResponse(200, body)    
    except ClientError as e:
    # Handle exceptions
        if e.response['Error']['Code'] == 'NoSuchKey':
            logger.error(f"The object {object_key} does not exist in the bucket.")
            return buildResponse(400, {"statusCode":400,"response":"failed","error":f"The object {object_key} does not exist in the bucket."}) 
        elif e.response['Error']['Code'] == 'AccessDenied':
            logger.error(f"Access to the object {object_key} is denied.")
            return buildResponse(400, {"statusCode":400,"response":"failed","error":f"Access to the object {object_key} is denied.}) 
        else:
            # Handle other errors
            logger.error(f"Error: {e}")
            return buildResponse(400, {"statusCode":400,"response":"failed","error":str(e)}) 
        except Exception as e:
        logger.error(e)
        return buildResponse(400, {"statusCode":400,"response":"failed","error":str(e)}) 
def buildResponse(statuscode, body=None):
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