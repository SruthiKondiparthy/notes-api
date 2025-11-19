# lambda_function.py
import os
import json
import logging
import uuid
import boto3
from botocore.exceptions import ClientError

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
TABLE_NAME = os.environ.get("TABLE_NAME", "Notes")

# DynamoDB client/resource
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)

# Helper response
def respond(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",           # adjust for prod
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization"
        },
        "body": json.dumps(body)
    }

def validate_note_body(body):
    if not isinstance(body, dict):
        return False, "Body must be a JSON object"
    if not body.get("title") or not isinstance(body.get("title"), str):
        return False, "Field 'title' is required and must be a string"
    if not body.get("content") or not isinstance(body.get("content"), str):
        return False, "Field 'content' is required and must be a string"
    return True, None

def lambda_handler(event, context):
    logger.info("Event received")
    logger.info(json.dumps(event))

    # Support both API Gateway v2 (HTTP API) and (fallback) REST style keys
    method = event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod")
    path = event.get("rawPath") or event.get("path") or ""
    body_raw = event.get("body")

    # Handle OPTIONS preflight quickly
    if method == "OPTIONS":
        return respond(204, {})

    # parse body safely
    try:
        body = json.loads(body_raw) if body_raw else {}
    except Exception as e:
        logger.error("Invalid JSON body: %s", e)
        return respond(400, {"message": "Request body must be valid JSON"})

    try:
        # CREATE
        if method == "POST" and path == "/notes":
            ok, err = validate_note_body(body)
            if not ok:
                return respond(400, {"message": err})

            note_id = str(uuid.uuid4())
            item = {
                "id": note_id,
                "title": body["title"],
                "content": body["content"]
            }
            table.put_item(Item=item)
            logger.info("Created note %s", note_id)
            return respond(201, item)

        # READ ALL
        if method == "GET" and path == "/notes":
            resp = table.scan()
            items = resp.get("Items", [])
            return respond(200, items)

        # READ ONE
        if method == "GET" and path.startswith("/notes/"):
            note_id = path.split("/")[-1]
            resp = table.get_item(Key={"id": note_id})
            item = resp.get("Item")
            if not item:
                return respond(404, {"message": "Note not found"})
            return respond(200, item)

        # UPDATE
        if method == "PUT" and path.startswith("/notes/"):
            note_id = path.split("/")[-1]
            ok, err = validate_note_body(body)
            if not ok:
                return respond(400, {"message": err})

            update_expr = "SET title = :t, content = :c"
            expr_vals = {":t": body["title"], ":c": body["content"]}

            # Optionally check existence first
            try:
                table.update_item(
                    Key={"id": note_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeValues=expr_vals,
                    ConditionExpression="attribute_exists(id)"  # prevents creating new item by update
                )
            except ClientError as ce:
                if ce.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    return respond(404, {"message": "Note not found"})
                raise
            logger.info("Updated note %s", note_id)
            return respond(200, {"message": "Note updated"})

        # DELETE
        if method == "DELETE" and path.startswith("/notes/"):
            note_id = path.split("/")[-1]
            # Use conditional delete to ensure it existed
            try:
                table.delete_item(
                    Key={"id": note_id},
                    ConditionExpression="attribute_exists(id)"
                )
            except ClientError as ce:
                if ce.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    return respond(404, {"message": "Note not found"})
                raise
            logger.info("Deleted note %s", note_id)
            return respond(200, {"message": "Note deleted"})

        # Not matched
        return respond(400, {"message": "Bad request"})

    except ClientError as e:
        logger.error("DynamoDB client error: %s", e)
        return respond(500, {"message": "Database error"})
    except Exception as e:
        logger.exception("Unexpected error")
        return respond(500, {"message": "Internal server error"})