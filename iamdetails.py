import boto3
iam_client = boto3.client('ec2',
                          'us-east-1',
                          aws_access_key_id='AKIAYH4L7KJ7VIMZ57HT',
                          aws_secret_access_key='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')


# response = iam_client.list_roles()  # Iterate through the roles
# for role in response['Roles']:
#     print(f"Role Name: {role['RoleName']}")
#     print(f"Role ARN: {role['Arn']}")
#     print(f"Assume Role Policy Document: {role['AssumeRolePolicyDocument']}")
#     print("\n")
# # iam = boto3.client("iam")
# paginator = ec2.get_paginator('list_users')
# for response in paginator.paginate():
#     for user in response["Users"]:
#         print(f"Username: {user['UserName']}, Arn: {user['Arn']}")

# Use the describe_security_groups method to retrieve information about all security groups
# response = ec2.describe_security_groups()

# # Check if there are security groups in the response
# if 'SecurityGroups' in response:
#     # Extract and print the names of the security groups
#     for security_group in response['SecurityGroups']:
#         print(f"Security Group Name: {security_group['GroupName']}")
# else:
#     print("No security groups found in the AWS account.")
# response = iam_client.describe_instances(InstanceIds=['i-07781c6333e53cb07'])
# print(response)
# for reservation in response['Reservations']:
#     # resourceparamter_fields["name"] = event_json_result['requests'][0]['resourceparamter']['name']
#     for instance in reservation['Instances']:
#         # resourceparamter_fields['subnet_id'] = instance['SubnetId']
#         print(instance['SubnetId'])

# Create a KMS client
kms_client = boto3.client('kms', 'us-east-1',
                          aws_access_key_id='AKIAYH4L7KJ7VIMZ57HT',
                          aws_secret_access_key='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')

# Use list_aliases to retrieve a list of KMS key aliases
response = kms_client.list_aliases()
print(response)
# # Extract the alias names from the response
# alias_names = [alias['AliasName'] for alias in response['Aliases']]

# # Print the list of custom KMS key alias names
# print("Custom KMS Key Alias Names:")
# for alias_name in alias_names:
#     print(alias_name)
# import boto3


# def ec2_instance_types():
#     '''Yield all available EC2 instance types in region <region_name>'''
#     ec2 = boto3.client('ec2', 'ap-south-1',
#                        aws_access_key_id='AKIAYH4L7KJ7VIMZ57HT',
#                        aws_secret_access_key='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')
#     describe_args = {}
#     while True:
#         describe_result = ec2.describe_instance_types(**describe_args)
#         yield from [i['InstanceType'] for i in describe_result['InstanceTypes']]
#         if 'NextToken' not in describe_result:
#             break
#         describe_args['NextToken'] = describe_result['NextToken']


# for ec2_type in ec2_instance_types():
#     print(ec2_type)
