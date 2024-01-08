#createdBy:NagaTriveni Singareddy
"""Description :Fetching AWS Instances details for a particular account using boto3 apis
to Fetch details and Hsm for authenciation of an account."""
"""Hardcoded code values: amazonMachineImage,vpcId,kmsKeyId we can fix these values once it  moved to genpact environment"""
# python version:3.11
#Modified On:10/10/2023
import boto3
import json
from customencoder import CustomEncoder
from datetime import datetime
from secret_key import get_secret
import botocore
from botocore.exceptions import ClientError,ParamValidationError,NoCredentialsError,EndpointConnectionError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
print(logger)
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
getMethod = 'GET'
dropdownpath = '/instance_dropdown_details'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path ==dropdownpath:
        response = get_dropdown_details(event['queryStringParameters']['cloudprovider'],event['queryStringParameters']['resource'],event['queryStringParameters']['accountid'])
    else:
        response = buildresponse(404, 'Not Found')

    return response
#Fetching details from boto3 apis and generating json based on inputs passed through query parameter of an api    
def get_dropdown_details(cloudprovider,resource,accountid):
    logger.info("entered dropdown_details_lambda  get_dropdown_details method")
    try:
        if((cloudprovider.lower()=='aws')and(resource.lower()=='ec2')):
            secret_value=json.loads(get_secret(accountid))
            ec2_client = boto3.client('ec2',
                           'us-east-1',
                           aws_access_key_id= secret_value['aws_access_key_id'],
                           aws_secret_access_key=secret_value['aws_secret_access_key'])
            keypairname = ec2_client.describe_key_pairs()
            instancetypes = ec2_client.describe_instance_types()
            availibilityzones = ec2_client.describe_availability_zones()
            volumetype = ec2_client.describe_volumes()
            subnet = ec2_client.describe_subnets()
            securitygroup=ec2_client.describe_security_groups()

                 
            instance_dropdown_output = {'accountId':accountid}
            instance_dropdown_input = {'tagname': [subnet,'Subnets','subnetID'], 'ZoneName': [availibilityzones,'AvailabilityZones','availabilityZone'], 
            'KeyName': [keypairname,'KeyPairs','keypairName'],
                                       'InstanceType': [instancetypes, 'InstanceTypes','instanceType'], 'VolumeType': [volumetype, 'Volumes','volumeType'],
                                       'AvailabilityZone': [volumetype, 'Volumes','EBSAvailabilityZone'],'KmsKeyId':[volumetype, 'Volumes','kmsKeyId'],
                                       'VpcId': [subnet, 'Subnets','vpcId'],
                                       'GroupName':[securitygroup,'SecurityGroups','securityGroupName'],'IAM Role Name':['pagnator','users']}
            for key, value in instance_dropdown_input.items():
                instancedetails = []
                if (key not in ['tagname','IAM Role Name','GroupName']):
                    [instancedetails.append({"value":data.get(key),"label":data.get(key)})
                     for data in value[0][value[1]] if data.get(key) not in [i['value'] for i in instancedetails ]]
                    instance_dropdown_output[value[2]] = instancedetails
                elif (key == 'IAM Role Name'):
                     ec2 = boto3.client('iam',
                     'us-east-1',
                      aws_access_key_id= secret_value['aws_access_key_id'],
                           aws_secret_access_key=secret_value['aws_secret_access_key'])

                     paginator = ec2.get_paginator('list_users')
                     for response in paginator.paginate():
                        for user in response["Users"]:
                            instancedetails.append({'value':user['UserName'],'label':user['UserName']})
                            logger.info(f"Username: {user['UserName']}, Arn: {user['Arn']}")
                     instance_dropdown_output['iamRoleName']= instancedetails 
                elif(key =='GroupName'):
                    [instancedetails.append({"value":data.get('GroupId'),"label":data.get(key)})
                     for data in value[0][value[1]] if data.get(key) not in [i['value'] for i in instancedetails ]]
                    instance_dropdown_output['securityGroupName'] = instancedetails
                else:
                    for data in value[0][value[1]]:
                        for tag in data.get('Tags', []):
                            if tag['Key'] == 'Name':
                                subnet_name = tag['Value']
                                instancedetails.append({'subnetId':data['SubnetId'],'subnetName':subnet_name})
                    instance_dropdown_output['subnetId'] = instancedetails
               
            # hardcoded values
            instance_dropdown_output['amazonMachineImage']=[{"value":"ami-1830440e","label":"ami-1830440e"},{"value":"ami-5247a23f","label":"ami-5247a23f"},{"value":"ami-1830440e","label":"ami-1830440e"}]
            instance_dropdown_output['vpcId']= instance_dropdown_output['vpcId'][0]
            instance_dropdown_output['kmsKeyId']= [{
                "value": "key1",
                "label": "key1"
            }]
            instance_dropdown_output['metaVersion']= [{
                "value": "V2 only",
                "label": "V2 only"
            },
            {
                "value": "V1 and V2 (optional)",
                "label": "V1 and V2 (optional)"
            }]
        logger.info(instance_dropdown_output)
        body = {
            'dropdown_Details': instance_dropdown_output
        }
        logger.info("ended dropdown_details_lambda  get_dropdown_details method")
        return buildresponse(200, body)
    except botocore.exceptions .ClientError as e:
        if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
            logger.error("Key pair does not exist.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidInstanceType.NotFound':
             logger.error("Instance type not found")  
             raise e 
        elif e.response['Error']['Code'] == 'InvalidVolumeType':
           logger.error("Invalid volume type. Specify a valid EBS volume type.") 
           raise e  
        elif e.response['Error']['Code'] == 'InvalidSubnetID.NotFound':
            logger.error("Subnet not found. Check the subnet ID.")  
            raise e 
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
               logger.error("You don't have permission to describe security groups.")
               raise e       
        else:
            logger.info(f"An error occurred: {e}")
    except ParamValidationError as e:
           logger.error(f"Parameter validation error: {e}")
           raise e
    except NoCredentialsError:
           logger.error("AWS credentials not found or configured incorrectly.")
           raise e
    except EndpointConnectionError as e:
           logger.error(f"Endpoint connection error: {e}")
           raise e
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