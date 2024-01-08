import boto3
import json
def file_reading(uuid):
    # Initialize the S3 client
    s3 = boto3.client('s3')
   # s3 = boto3.client('s3')
    #print(s3)
    # Specify the S3 bucket and object key (path to the file)
    bucket_name = 'gen-mohammadbucket'
    folder=uuid+"-EventJson"
    filename=uuid+"_event.json"

    object_key = "events"+"/"+folder+"/"+filename
    print(object_key)

    try:
        # Read the contents of the S3 object
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        content = response['Body'].read().decode('utf-8')
        
        # Process the content (you can modify this part to suit your needs)
        # For example, you can log the content or perform some operations on it.
        print(content)
        
        # Return a response if needed
        return content
    except Exception as e:
        print(f"Error: {str(e)}")
        return e