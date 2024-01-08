import boto3
def get_secret(secret_name, region_name=None):
    region_name = "us-east-1"
    session = boto3.session.Session()
    client = session.client(
            service_name='secretsmanager',
            region_name=region_name or session.region_name,
        )

    response = client.get_secret_value(SecretId=secret_name)

    if 'SecretString' in response:
        secret = response['SecretString']
    else:
        # If the secret is stored as binary, you may need additional processing
        secret = response['SecretBinary']

    return secret