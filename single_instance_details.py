#createdBy:NagaTriveni Singareddy
"""Description :Fetching AWS Instances details for a particular instance using boto3 apis
"""
"""Hardcoded code values: ebsconfig,iam,kmsKeyId we can fix these values once it  moved to genpact environment"""
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
#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
getMethod = 'GET'
dropdownpath = '/instance_dropdown_details'
def lambda_handler(event: dict, context: LambdaContext)->str:
    logger.info(event)
    httpmethod = event['httpMethod']
    path = event['path']
    if httpmethod == getMethod and path ==dropdownpath:
        response = final_instance_details(event['queryStringParameters']['accountid'],event['queryStringParameters']['instanceid'],event['queryStringParameters']['uuid'])
    else:
        response = buildresponse(404, 'Not Found')

    return response
ec2 = boto3.client('ec2')
response = ec2.describe_instances(InstanceIds=['i-07781c6333e53cb07'])
event_json_result = json.loads(file_reading(uuid))

def instance_tags(instancetags):
    tags_dict = {}
    for tag in instancetags:

        tags_dict[tag['Key']] = tag['Value']
    return tags_dict


def securitygroup_details(security_group_ids, ec2):

    security_dict = []
    for security_group_id in security_group_ids:
        print("securityid", security_group_id)
        security_group_response = ec2.describe_security_groups(
            GroupIds=[security_group_id['GroupId']]
        )
       # print(security_group_response)
        groupname = security_group_id['GroupName']
        for security_group in security_group_response['SecurityGroups']:
           # print("securitygroup", security_group)
            ingress = permissions(security_group['IpPermissions'])
            egress = permissions(security_group['IpPermissionsEgress'])
        security_dict.append(
            [{"securityGroupName": groupname, "ingress": ingress, "egress": egress}])
    # print("securitydict", security_dict)
    return security_dict


def permissions(permissionstype):
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
    return permission_value


def volume_details(volumeids, ec2):
    volumedetails = []
    for volume_id in volumeids:
        response = ec2.describe_volumes(VolumeIds=[volume_id])
        volume_dict = {}
        for volume in response['Volumes']:
            volume_dict['volume_type'] = volume['VolumeType']
            volume_dict["delete_on_termination"] = volume['Attachments'][0]['DeleteOnTermination']
            volume_dict["volume_size"] = volume['Size']
            volume_dict["encrypted"] = volume['Encrypted']
            volume_dict["kms_key_id"] = volume.get('KmsKeyId', 'N/A')
            volume_dict["iops"] = volume.get('Iops', 'N/A')
        volumedetails.append(volume_dict)
    return volumedetails
def dropdown_security(response):
     dropdown_security_list=[]

     if 'Reservations' in response:
         reservation = response['Reservations'][0]
         instance = reservation['Instances'][0]

        # Extract and print the security group IDs associated with the instance
         security_group_ids = instance['SecurityGroups']
         for sg in security_group_ids:
            drop_down_security_dict={"value":sg['GroupId'],"lable":sg['GroupName']}
            dropdown_security_list.append( drop_down_security_dict)
     return  dropdown_security_list      

        

def resource_parameter_fields(response, event_json_result):
    resourceparamter_fields = {}
    security_group_ids = []
    volumeids = []
    for reservation in response['Reservations']:
        resourceparamter_fields["name"] = event_json_result['requests'][0]['resourceparamter']['name']
        for instance in reservation['Instances']:
            resourceparamter_fields['subnet_id'] = instance['SubnetId']
            resourceparamter_fields['availability_zone'] = instance['Placement']['AvailabilityZone']
            resourceparamter_fields['vpc_id'] = instance['VpcId']
            resourceparamter_fields['image_id'] = instance['ImageId']
            resourceparamter_fields['instance_type'] = instance['InstanceType']
            resourceparamter_fields['key_name'] = instance['KeyName']
            resourceparamter_fields['source_destination'] = instance['SourceDestCheck']
            if 'Tags' in instance:
                tags = instance['Tags']
                result_tags = instance_tags(tags)
                # print(f"Tags for Instance ID: {instance_id}")
                print("result_tags", result_tags)
            resourceparamter_fields['tags'] = result_tags
            security_group_ids.extend(instance['SecurityGroups'])
            print("securitygroupids", security_group_ids)
            result = securitygroup_details(security_group_ids, ec2)
            resourceparamter_fields['securitydetails'] = result
           # print("securitygroup", instance['SecurityGroups'])
            if 'BlockDeviceMappings' in instance:
                for block_device_mapping in instance['BlockDeviceMappings']:
                    volume_id = block_device_mapping['Ebs']['VolumeId']
                    volumeids.append(volume_id)
                    print(f"Volume ID: {volume_id}")
            resourceparamter_fields['root_block_device'] = volume_details(
                volumeids, ec2)
    #Hardcoded value iamrole and description
    resourceparamter_fields["iam_role_name"]: [
                    "TESTCASE10NOV2022"]
    resourceparamter_fields["description"]: "TESTCASE10NOV2022"
    #hardcoded value
    resourceparamter_fields["ebs_config"]: [
                    {
                        "index": 1,
                        "size": 100,
                        "availability_zone": "us-east-1c",
                        "kms_key_id_ebs": ""
                    }
                ]
            
    resourceparamter_fields["managed_policy_arns"] = event_json_result['requests'][0]['resourceparamter']['managed_policy_arns']
    resourceparamter_fields["inline_policy"] = event_json_result['requests'][0]['resourceparamter']["inline_policy"]
    resourceparamter_fields["create_instance_profile"] = event_json_result[
        'requests'][0]['resourceparamter']["create_instance_profile"]
    resourceparamter_fields["assumerolepolicyjson"] = event_json_result['requests'][0]['resourceparamter']["assumerolepolicyjson"]
    resourceparamter_fields["jsonfiles"] = event_json_result['requests'][0]["jsonfiles"]
    return resourceparamter_fields
def subnetname(response):
    subnet_dict={}
# Describe the subnet to get its tags
    if 'Reservations' in response:
        reservation = response['Reservations'][0]
        instance = reservation['Instances'][0]

    # Extract the subnet ID associated with the instance
        subnet_id = instance['SubnetId']
        subnet_dict['subnetId']=subnet_id
    # Now, let's retrieve information about the subnet
        ec2_resource = boto3.resource('ec2')
        subnet = ec2_resource.Subnet(subnet_id)

    # Retrieve and print the subnet name and ID
        subnet_name = subnet.tags[0]['Value'] if subnet.tags else "N/A"
        subnet_dict['subnetName']=subnet_name
    return subnet_dict
def dropdown_result_values(value):
    dropdown_result_list=[]
    if isinstance(value,list):
        for i in value:
            dropdown_result_list.append({'value':i,'lable':i})
        return dropdown_result_list    
    else:
        return  {'value':value,'lable':value}       

def get_table_details(accountid):
    accountdetails_table= 'accountdetails_masterdata'
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(accountdetails_table)
    logger.info("entered usermanagement_lambda  get_table_details method")
    dynamodbtablename = table
    table = dynamodb.Table(dynamodbtablename)
    response = table.scan(
    FilterExpression=Attr('accountid').eq(accountid))
    items = response.get('Items',[])
    return items
def dropdown_details(accountid,response,event_json_result):
    dropdown_details_dict={}
    dropdown_details_dict["subnetId"]=subnetname(response)
    resource_parameter_result=resource_parameter_fields(response,event_json_result)
    dropdown_details_dict["accountId"]=get_table_details(accountid)
    dropdown_details_dict["availabilityZone"]=dropdown_result_values(resource_parameter_result['availability_zone'])
    dropdown_details_dict["instanceType"]=dropdown_result_values(resource_parameter_result['instance_type'])
    dropdown_details_dict["keypairName"]=dropdown_result_values(resource_parameter_result['key_name'])
    dropdown_details_dict["volumeType"]=dropdown_result_values(resource_parameter_result['root_block_device'][0]["volume_type"])
    dropdown_details_dict["vpcId"]=dropdown_result_values(resource_parameter_result['vpc_id'])
    dropdown_details_dict[ "amazonMachineImage"]=dropdown_result_values(resource_parameter_result['image_id'])
    dropdown_details_dict["securityGroupName"]=dropdown_security(response)
    dropdown_details_dict["kmsKeyId"]=[
            {
                "value": "key1",
                "label": "key1"
            }]
    #hardcoded value iam rolename
    dropdown_details_dict["iamRoleName"]=[{"value":"automation","lable":"automation"}]
    dropdown_details_dict["description"]="TESTCASE10NOV2022"
    return dropdown_details_dict

def request_fields(response, event_json_result, uuid):
    requests = []
    request_dict = {}
    request_dict["seqnumber"]: uuid.split("-")[2]
    request_dict["env"] = event_json_result[requests][0]["env"]
    request_dict["platform"] = event_json_result[requests][0]["platform"]
    request_dict["region"]: resource_parameter_fields(response, event_json_result)[
        "availability_zone"][:-1]
    request_dict["accountid"] = response['Reservations'][0]['OwnerId'],
    request_dict["action"] = event_json_result[requests][0]["deploy"],
    request_dict["resourcetype"] = event_json_result[requests][0]["resourcetype"]
    request_dict["cibuildid"] = event_json_result[requests][0]["cibuildid"]
    request_dict["prid"]: event_json_result[requests][0]["prid"]
    request_dict["uuid"]: uuid
    request_dict["resourceparamter"] = resource_parameter_fields(
        response, event_json_result)
    requests.append(request_dict)
    return requests

def final_instance_details(accountid,instance_id,uuid):
    logger.info("entered dropdown_details_lambda  get_dropdown_details method")
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances(InstanceIds=[instance_id])
        event_json_result = json.loads(file_reading(uuid))

        final_instance_details_dict = {}
        final_instance_details_dict["apiversion"] = event_json_result["apiversion"]
        final_instance_details_dict["ticketid"] = uuid.split("-")[0]
        final_instance_details_dict["projectid"] = uuid.split("-")[1]
        final_instance_details_dict["changeticketid"] = uuid.split("-")[0]
        final_instance_details_dict["description"] = event_json_result["description"]
        final_instance_details_dict["attemptid"] = uuid.split("-")[-1]
        final_instance_details_dict["gitorgname"] = event_json_result["gitorgname"]
        final_instance_details_dict["requests"] = request_fields(response,
                                                                event_json_result, uuid)
        final_instance_details_dict['dropdown_details']=dropdown_details(accountid,response,event_json_result)
        body = {
            'single_instnace_details': final_instance_details_dict
        }
        logger.info("ended single_instance_details_lambda   final_instance_details method")
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
    except Exception as e:
           logger.error("exception found",e)

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