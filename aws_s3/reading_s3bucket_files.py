import boto3
import json


def file_reading(uuid, accountid):
    # Initialize the S3 client
    s3 = boto3.client('s3')
   # s3 = boto3.client('s3')
    # print(s3)
    # Specify the S3 bucket and object key (path to the file)
    bucket_name = 'gen-mohammadbucket'
    folder = uuid+"-EventJson"
    filename = uuid+"_event.json"
    object_key = "events"+"/"+folder+"/"+filename
    logger.info(object_key)
    # Read the contents of the S3 object
    response = s3.get_object(Bucket=bucket_name, Key=object_key)
    content = response['Body'].read().decode('utf-8')
    logger.info(content)
    # Return a response if needed
    return content
