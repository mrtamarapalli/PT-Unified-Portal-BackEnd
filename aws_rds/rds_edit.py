"""Description :Fetching AWS rds database  details for a particular bucket using boto3 apis
"""

# python version:3.11
#Modified On:19/10/2023
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
dropdownpath = '/edit_details'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    logger.info("entered dropdown_details_lambda  lambda_handler")
    httpmethod = event['httpMethod']
    path = event['path']
    parameters=event['queryStringParameters']
    if httpmethod == getMethod and path ==dropdownpath:
        response = final_dbinstanceidentifier_details(param1,parm2,param3)
    else:
        logger.error("path or method not found")
        response = buildresponse(404, {"statusCode":404,"response":"failed","error":"path or method not found"})
    
    logger.info("ended dropdown_details_lambda  lambda_handler")
    return response
def rds_tags(instancetags):
    tags_dict = {}
    for tag in instancetags:

        tags_dict[tag['Key']] = tag['Value']
    return tags_dict

def dbparametergroup(dbparametergroups):
    rds_client = boto3.client('rds')
    parametergroup_response = rds_client.describe_db_parameter_groups(
        DBParameterGroupName=dbparametergroups)
    result = parametergroup_response['DBParameterGroups'][0]['DBParameterGroupFamily']
    return result


def option_group(optiongroupname):
    rds_client = boto3.client('rds')
    optiongroup_response = rds_client.describe_option_groups(
        OptionGroupName=optiongroupname)
    result = {}
    result['MajorEngineVersion'] = optiongroup_response['OptionGroupsList'][0]['MajorEngineVersion']
    result['OptionGroupDescription'] = optiongroup_response['OptionGroupsList'][0]['OptionGroupDescription']
    print(result)
    return result

def resource_parameter_fields(accountid,response,event_json_result):
    logger.info("entered dropdown_details_lambda  resource_parameter_fields methods")
    resource_parameter_dict = {}
    for value in response['DBInstances']:
        # print(value)
        # print(response['DBInstances'][0][value])
        resource_parameter_dict["identifier"] = value['DBInstanceIdentifier']
        # hardcoded value
        resource_parameter_dict["db_name"] = value['DBName']
        resource_parameter_dict["engine"] = value['Engine']
        resource_parameter_dict["engine_version"] = value['EngineVersion']
        resource_parameter_dict["instance_class"] = value["DBInstanceClass"]
        resource_parameter_dict["allocated_storage"] = value["AllocatedStorage"]
        resource_parameter_dict["storage_type"] = value["StorageType"]
        resource_parameter_dict["storage_encrypted"] = value["StorageEncrypted"]
        resource_parameter_dict["multi_az"] = value["MultiAZ"]
        resource_parameter_dict["subnet_group_name"] = value["DBSubnetGroup"]["DBSubnetGroupName"]
        resource_parameter_dict["vpc_id"] = value["DBSubnetGroup"]["VpcId"]
        resource_parameter_dict["license_model"] = value["LicenseModel"]
        resource_parameter_dict["maintenance_window"] = value["PreferredMaintenanceWindow"]
        resource_parameter_dict["backup_window"] = value["PreferredBackupWindow"]
        resource_parameter_dict["apply_immediately"] = value["PreferredBackupWindow"]
		resource_parameter_dict["timezone"] = ""
		resource_parameter_dict["delete_automated_backups"]=True
	    resource_parameter_dict["enabled_cloudwatch_logs_exports"]=value['EnabledCloudwatchLogsExports']
        resource_parameter_dict["kms_key_id"] = value["KmsKeyId"]
        resource_parameter_dict["deletion_protection"] = value["DeletionProtection"]
        resource_parameter_dict["performance_insights_enabled"] = value["PerformanceInsightsEnabled"]
        resource_parameter_dict["performance_insights_retention_period"] = value["PerformanceInsightsRetentionPeriod"]
        resource_parameter_dict["performance_insights_kms_key_id"] = value["PerformanceInsightsKMSKeyId"]
        # resource_parameter_dict["iops"] = value["IOPS"]
        # resource_parameter_dict["port"] = value["Port"]
        # resource_parameter_dict["create_db_option_group"]=True,
        # dbparametergroups = []
        # for i in value['DBParameterGroups']:
        # dbparametergroups.append(i['DBParameterGroupName'])
        dbparametergroups = value['DBParameterGroups'][0]['DBParameterGroupName']
        resource_parameter_dict["family"] = dbparametergroup(dbparametergroups)
        optiongroupname = value['OptionGroupMemberships'][0]['OptionGroupName']
        optiongroup_result = option_group(optiongroupname)
        resource_parameter_dict["major_engine_version"] = optiongroup_result['MajorEngineVersion']
        resource_parameter_dict["option_group_description"] = optiongroup_result['OptionGroupDescription']
        resource_parameter_dict["tags"] = rds_tags(value['TagList'])
        return resourceparamter_fields
def request_fields(accountid,response,event_json_result,uuid):
    logger.info("entered dropdown_details_lambda  request_fields method")
    requests = []
    request_dict = {}
    request_dict["seqnumber"]: uuid.split("-")[2]
    request_dict["env"] = event_json_result[requests][0]["env"]
    request_dict["platform"] = event_json_result[requests][0]["platform"]
    request_dict["region"]=response['DBInstances']
        "availability_zone"][:-1]
    request_dict["accountid"] = accountid
    request_dict["action"] = event_json_result[requests][0]["deploy"]
    request_dict["resourcetype"] = event_json_result[requests][0]["resourcetype"]
    request_dict["cibuildid"] = event_json_result[requests][0]["cibuildid"]
    request_dict["prid"]=event_json_result[requests][0]["prid"]
    request_dict["uuid"]=uuid
    request_dict["resourceparamter"] = resource_parameter_fields(
        accountid,db_instance_identifier,event_json_result)
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
    resource_parameter_result=resource_parameter_fields(accountid,response,event_json_result)
    dropdown_details_dict["accountId"]=get_table_details(accountid)
    dropdown_details_dict["engine"]=dropdown_result_values(resource_parameter_result['engine'])
    dropdown_details_dict["major_engine_version"]=dropdown_result_values(resource_parameter_result["major_engine_version"])
    dropdown_details_dict["engine_version"]=dropdown_result_values(resource_parameter_result["engine_version"])
    dropdown_details_dict["performance_insights_kms_key_id"]=dropdown_result_values(resource_parameter_result["performance_insights_kms_key_id"])
    dropdown_details_dict["kms_key_id"]=dropdown_result_values(resource_parameter_result["kms_key_id"])
    dropdown_details_dict["family"]=dropdown_result_values(resource_parameter_result["family"])
    dropdown_details_dict["subnet_group_name"]=dropdown_result_values(resource_parameter_result["subnet_group_name"])
    logger.info("ended dropdown_details_lambda  dropdown_details method")
    return dropdown_details_dict

def final_dbinstanceidentifier_details(accountid,db_instance_identifier,uuid):
    logger.info("entered dropdown_details_lambda  final_bucket_details method")
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
        event_json_result = json.loads(file_reading(uuid))
        final_dbinstanceidentifier_dict = {}
        final_dbinstanceidentifier_dict["apiversion"] = event_json_result["apiversion"]
        final_dbinstanceidentifier_dict["ticketid"] = uuid.split("-")[0]
        final_dbinstanceidentifier_dict["projectid"] = uuid.split("-")[1]
        final_dbinstanceidentifier_dict["changeticketid"] = uuid.split("-")[0]
        final_dbinstanceidentifier_dict["description"] = event_json_result["description"]
        final_dbinstanceidentifier_dict["attemptid"] = uuid.split("-")[-1]
        final_dbinstanceidentifier_dict["gitorgname"] = event_json_result["gitorgname"]
        final_dbinstanceidentifier_dict["requests"] = request_fields(accountid,bucketname,
                                                                event_json_result,uuid)
        final_dbinstanceidentifier_dict['dropdown_details']=dropdown_details(accountid,bucketname,uuid,event_json_result)
        body = {
            'statuscode':200,
            'response':"sucess",
            'rdsEditDetails': final_dbinstanceidentifier_dict
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
        response['body'] = json.dumps(body)
    return response                