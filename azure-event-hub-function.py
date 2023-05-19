import logging
import azure.functions as func
import boto3
import botocore
import json
from botocore.exceptions import ClientError

SECURITY-LAKE-AZURE-STREAM-ARN = ""
SECURITY-LAKE-AZURE-STREAM-NAME = ""
SECURITY-LAKE-AZURE-KEYID = ""

def main(event: func.EventHubEvent):

    kinesis_client = boto3.client('kinesis')
    
    response = kinesis_client.start_stream_encryption(
        StreamName=SECURITY-LAKE-AZURE-STREAM-NAME,
        EncryptionType='KMS',
        KeyId=SECURITY-LAKE-AZURE-KEYID,
        StreamARN=SECURITY-LAKE-AZURE-STREAM-ARN
    )

    for i in event:
        event_data_raw = i.get_body().decode('utf-8')

        for record in json.loads(event_data_raw)["records"]:
            logging.info(record)
            logging.info(type(record))

            response = kinesis_client.put_record(StreamName=SECURITY-LAKE-AZURE-STREAM-ARN, 
            Data=json.dumps(record), 
            PartitionKey="time"
)

