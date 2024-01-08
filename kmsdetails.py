import boto3
 
# Create KMS client
kms_client = boto3.client('kms')
 
# Retrieve all KMS keys
response = kms_client.list_keys()
 
for key in response['Keys']:
    key_id = key['KeyId']
    # Get alias name for the KMS key
    try:
        alias_response = kms_client.list_aliases(KeyId=key_id)
        alias_name = alias_response['Aliases'][0]['AliasName']
        print(f"KMS Key ID: {key_id}")
        print(f"Alias Name: {alias_name}")
        print("------")
    except Exception as e:
        print(f"Error retrieving alias for Key ID: {key_id}. Error: {str(e)}")
import boto3

def get_all_kms_keys():
    kms_client = boto3.client('kms')

    # Initial request to list KMS keys
    response = kms_client.list_keys()

    # List to store all KMS keys
    all_keys = response['Keys']

    # Continue making requests until truncated is False
    while response.get('Truncated', False):
        # Use Marker from the previous response to paginate
        response = kms_client.list_keys(Marker=response['NextMarker'])
        all_keys.extend(response['Keys'])

    return all_keys

# Example usage
all_keys = get_all_kms_keys()

# Print the ARN of each KMS key
for key in all_keys:
    print(f"Key ARN: {key['KeyArn']}")

