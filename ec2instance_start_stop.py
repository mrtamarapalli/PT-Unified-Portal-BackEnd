import boto3
import botocore.exceptions
import json


def buildResponse(statusCode, body=None):
    response = {
        'statusCode': statusCode,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body)
    return response


def lambda_handler(event, context):
    try:
        # Check if the event contains the required parameters
        if event['httpMethod'] != 'POST':
            return {
                'statusCode': 405,
                'body': 'Invalid HTTP method. Only POST is allowed.'
            }

        # Parse the JSON body of the POST request
        request_body = json.loads(event['body'])

        if 'instance_id' not in request_body or 'action' not in request_body:
            return {
                'statusCode': 400,
                'body': 'Missing instance_id or action parameter in the request body.'
            }
        # Retrieve the instance ID and action from the request body
        instance_id = request_body['instance_id']
        # Convert the action to lowercase
        action = request_body['action'].lower()
        # Validate the action (start or stop)
        if action not in ['start', 'stop']:
            return {
                'statusCode': 400,
                'body': 'Invalid action. Supported actions are start or stop.'
            }

        # Create an EC2 client
        ec2_client = boto3.client('ec2')

        if action == 'start':
            # Start the EC2 instance
            ec2_client.start_instances(InstanceIds=[instance_id])
        elif action == 'stop':
            # Stop the EC2 instance
            ec2_client.stop_instances(InstanceIds=[instance_id])
        else:
            return {
                'statusCode': 400,
                'body': 'Invalid action. Supported actions are start or stop.'
            }

        return buildResponse(200, f'Successfully {action}ed instance {instance_id}.')
    except botocore.exceptions.ClientError as e:
        error_message = e.response['Error']['Message']
        return buildResponse(500, f'AWS Error: {error_message}')
    except Exception as e:
        return buildResponse(500, f'Error: {str(e)}')
