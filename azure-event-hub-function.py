import logging
import azure.functions as func
import boto3
import botocore
import json
from botocore.exceptions import ClientError

SECURITY_LAKE_AZURE_STREAM_ARN = ""
SECURITY_LAKE_AZURE_STREAM_NAME = ""
SECURITY_LAKE_AZURE_KEYID = ""

def main(event: func.EventHubEvent):

    kinesis_client = boto3.client('kinesis')
    
    response = kinesis_client.start_stream_encryption(
        StreamName=SECURITY_LAKE_AZURE_STREAM_NAME,
        EncryptionType='KMS',
        KeyId=SECURITY_LAKE_AZURE_KEYID,
        StreamARN=SECURITY_LAKE_AZURE_STREAM_ARN
    )

    for i in event:
        event_data_raw = i.get_body().decode('utf-8')

        for record in json.loads(event_data_raw)["records"]:
            logging.info(record)
            logging.info(type(record))

            response = kinesis_client.put_record(StreamName=SECURITY_LAKE_AZURE_STREAM_ARN, 
            Data=json.dumps(record), 
            PartitionKey="time"
)

