import json
import boto3
from boto3.dynamodb.conditions import Key

def lambda_handler(event, context):
    url_path = event["path"]
    http_method = event["httpMethod"]
    
    try:
        if url_path == "/useroperations" and http_method == "GET":
            response = get_user_operations()
        else:
            response = build_response(400, {"error": "Data Not Found"})
                
        return response
    
    except Exception as e:
        return build_response(500, {"Error": str(e)})

def get_user_operations():
    dynamodb = boto3.resource("dynamodb")
    operations_table = dynamodb.Table("operations")
    role_mapping_table = dynamodb.Table("operationsrole_mapping")
    
    role_mapping_items = role_mapping_table.scan(ProjectionExpression="role_id, operation_id, status")["Items"]
    operations_items = operations_table.scan(ProjectionExpression="cloudprovider, id, operation")["Items"]
    
    l1_operation_id = get_operations_by_role(role_mapping_items, "1")
    l2_operation_id = get_operations_by_role(role_mapping_items, "2")
    l3_operation_id = get_operations_by_role(role_mapping_items, "3")
    
    cloud_providers = list(set(item["cloudprovider"] for item in operations_items))
    
    l3_operations = get_provider_operations(operations_items, l3_operation_id, cloud_providers)
    l2_operations = get_provider_operations(operations_items, l2_operation_id, cloud_providers)
    l1_operations = get_provider_operations(operations_items, l1_operation_id, cloud_providers)
    
    result = {"L1 Operations": l1_operations, "L2 Operations": l2_operations, "L3 Operations": l3_operations}
    
    body = {"user_operations": result}
    
    return build_response(200, body)

def get_operations_by_role(role_mapping_items, role_id):
    return [item["operation_id"] for item in role_mapping_items if item["role_id"] == role_id and item["status"] == "active"]

def get_provider_operations(operations_items, operation_ids, cloud_providers):
    result = []
    for provider in cloud_providers:
        provider_operations = {"provider": provider, "operations": [item["operation"] for item in operations_items if item["cloudprovider"] == provider and item["id"] in operation_ids]}
        result.append(provider_operations)
    return result

def build_response(status_code, body=None):
    response = {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    }
    if body is not None:
        response["body"] = json.dumps(body)
    return response
