#createdBy:NagaTriveni Singareddy
"""Description :Fetching securitygroup details based on security_id"""
# python version:3.11
#Modified On:12/10/2023
import boto3
import json
from customencoder import CustomEncoder
from datetime import datetime
from secret_key import get_secret
from botocore.exceptions import ClientError, ParamValidationError, NoCredentialsError,EndpointConnectionError
# import logging 
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
logger = Logger(service="IAC_MW_GIT_OPETATION", name="IACGitInterface")
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
patch_all()
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)
postMethod = 'POST'
securitygroupdetailspath = '/securitygroupdetails'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event["httpMethod"]
    path = event['path']
    if httpmethod == postMethod and path ==securitygroupdetailspath:
         if 'body' in event:
             try:
                 data = json.loads(event['body'])
                 response = get_securitygroup_details(data['groupid'],data['accountid'])
             except json.JSONDecodeError as e:
                    body={
                        'error': json.dumps({'error': 'Invalid JSON format'})}
                    return buildresponse(400, body)
         else:         
              response = buildresponse(404, ' data Not Found')
    else:
        response = buildresponse(404, 'Not Found')

    return response
#Fetching details from boto3 apis and generating json based on inputs passed through query parameter of an api    
def  get_securitygroup_details(groupid,accountid):
    logger.info("entered securitygroupdetails_details_lambda  get_securitygroup_details method")
    try:
        security_details_list=[]
        secret_value=json.loads(get_secret(accountid))
        ec2_client = boto3.client('ec2',
                           'us-east-1',
                           aws_access_key_id= secret_value['aws_access_key_id'],
                           aws_secret_access_key=secret_value['aws_secret_access_key'])
        for groupid in groupid:
            security_group_response = ec2_client.describe_security_groups(
                GroupIds=[groupid])
           # print(security_group_response)
            
            for security_group in security_group_response['SecurityGroups']:
               #print("securitygroup", security_group)
               groupname = security_group['GroupName']
               ingress = permissions(security_group['IpPermissions'])
               egress = permissions(security_group['IpPermissionsEgress'])
    
               
            security_dict={"securityGroupName": groupname, "ingress": ingress,"egress":egress,"groupid":groupid}
            security_details_list.append( security_dict)
      
        logger.info("ended securitygroupdetails_details_lambda  get_securitygroup_details method")            
        body = {
            'securitygroup_Details': security_details_list
        }
        return buildresponse(200, body)
    except ClientError as e:
           if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
              logger.error("Security group not found.")
              raise e
           elif e.response['Error']['Code'] == 'UnauthorizedOperation':
               logger.error("You don't have permission to describe security groups.")
               raise e
           else:
                 logger.error(f"An error occurred: {e}")
                 raise e
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
def permissions(permissionstype):
    logger.info("entered securitygroupdetails_details_lambda permissions method")
    index = 0
    permission_value=[]
    for rule in permissionstype:
        
        permission_rule_dict = {}
        index=index+1
        permission_rule_dict['index'] = index
        permission_rule_dict["from_port"] = rule.get('FromPort')
        permission_rule_dict['to_port'] = rule.get('ToPort')
        permission_rule_dict['protocol'] = rule.get('IpProtocol')
        permission_rule_dict['description'] = rule.get('Description', 'No description provided')
        ip_ranges = rule.get('IpRanges', [])
        ipv6_ranges = rule.get('Ipv6Ranges', [])
        cidr_blocks = []
        for ip_range in ip_ranges:
            cidr_ip = ip_range['CidrIp']
            cidr_blocks.append(cidr_ip)
        permission_rule_dict['cidr_blocks'] = cidr_blocks
        ipv6_cidr_blocks = []
        for ipv6_range in ipv6_ranges:
            ipv6 = ipv6_range['CidrIpv6']
            ipv6_cidr_blocks.append(ipv6)
        permission_rule_dict['ipv6_cidr_blocks'] = ipv6_cidr_blocks
        
        source_security_group_id=[]
        if 'UserIdGroupPairs' in rule:
            # print(rule['UserIdGroupPairs'])
            if (rule['UserIdGroupPairs']):
                for group_pair in rule['UserIdGroupPairs']:
                    # print("grouppair", group_pair)
                    source_security_group_id.append(group_pair.get(
                        'GroupId', 'N/A'))
            else:
                 source_security_group_id=None      
            
        permission_rule_dict["source_security_group_id"]=source_security_group_id
        permission_value.append(permission_rule_dict)
    logger.info(permission_value)    
    logger.info("ended securitygroupdetails_details_lambda permissions method")    
    return permission_value