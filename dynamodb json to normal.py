import boto3
from boto3.dynamodb.types import TypeDeserializer

# Initialize the TypeDeserializer
deserializer = TypeDeserializer()

# Your DynamoDB JSON
dynamodb_json = {
    'Name': {'S': 'John'},
    'Age': {'N': '30'},
    'IsStudent': {'BOOL': True},
    'Interests': {'SS': ['Reading', 'Hiking']},
    'Address': {'M': {'City': {'S': 'New York'}, 'State': {'S': 'NY'}}}
}

# Convert DynamoDB JSON to standard JSON
standard_json = {key: deserializer.deserialize(value) for key, value in dynamodb_json.items()}

print(standard_json)
# termination protection
response = ec2_client.describe_instance_attribute(
    InstanceId=instance_id,
    Attribute='disableApiTermination'
)
print(response)
# Check the value of 'DisableApiTermination' to see if termination protection is enabled
termination_protection_enabled = response['DisableApiTermination']['Value']