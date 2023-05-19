import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame
from pyspark.sql.functions import *
from pyspark.sql.types import *

from pyspark.sql import DataFrame, Row
import datetime
from awsglue import DynamicFrame

args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

AWS_REGION_NAME = ""
AWS_ACCOUNT_ID = ""
SECURITY-LAKE-AZURE-STREAM-ARN = ""
DATA_LAKE_NAME = ""

# Script generated for node Kinesis Stream
dataframe_KinesisStream_node1 = glueContext.create_data_frame.from_options(
    connection_type="kinesis",
    connection_options={
        "typeOfData": "kinesis",
        "streamARN": SECURITY-LAKE-AZURE-STREAM-ARN,
        "classification": "json",
        "startingPosition": "earliest",
        "inferSchema": "true",
    },
    transformation_ctx="dataframe_KinesisStream_node1",
)


def processBatch(data_frame, batchId):
    if data_frame.count() > 0:
        KinesisStream_node1 = DynamicFrame.fromDF(
            data_frame, glueContext, "from_data_frame"
        )
        # Script generated for node ApplyMapping
        ApplyMapping_node2 = ApplyMapping.apply(
            frame=KinesisStream_node1,
            mappings=[
                 ("operationName", "string", "api.operation", "string"), 
                 ("identity.authorization.scope", "string", "resources.details", "string"), 
                 ("caller", "string", "identity.user.uid", "string"), 
                 ("identity.claims.ipaddr", "string", "src_endpoint.ip", "string"),
                 ("identity.claims.name", "string", "identity.user.name", "string"),
                 ("time", "string", "time", "string"), 
                 ("level", "string", "severity", "string"), 
                 ("identity.claims.groups", "string", "resources.group_name", "string"),
                 ("resourceId", "string", "resource.owner.uid", "string"), 
                 ("properties.message", "string", "message", "string"),
                 ("claims.ver", "string", "metadata.product.version", "string"),
             ],
            transformation_ctx="ApplyMapping_node2",
        )
        ApplyMapping_node2.printSchema()
        ApplyMapping_node2.show(5)
        
        #add OCSF base fields
        azureAuditLog_df = ApplyMapping_node2.toDF().withColumn("activity_id",lit("3"))\
                                                             .withColumn("activity_name", lit("Operational"))\
                                                             .withColumn("category_name", lit("Audit Activity"))\
                                                             .withColumn("category_uid", lit("3"))\
                                                             .withColumn("class_name", lit("API Activity"))\
                                                             .withColumn("class_uid", lit("3005"))
                                                               
        azureAuditLog_df = azureAuditLog_df.withColumn('metadata', struct([col('metadata')['product'].alias("product"), lit("Azure Audit Logs").alias('name'), lit("[]").alias('profiles'), lit("1.0").alias('version')]))
        azureAuditLog_df = azureAuditLog_df.withColumn("unmapped", lit("[]"))
        azureAuditLog_df_dynf = DynamicFrame.fromDF(azureAuditLog_df, glueContext, "dynamic_frame").repartition(1)
        
        now = datetime.datetime.now()
        year = now.year
        month = now.month
        day = now.day
        hour = now.hour
        region = AWS_REGION_NAME
        account_id = AWS_ACCOUNT_ID


        # Script generated for node S3 bucket
        S3bucket_node3_path = (
            DATA_LAKE_NAME+"/ext/AZURE-ACTIVITY"
            + "/region=" 
            + region 
            + "/account_id=" 
            + account_id 
            + "/eventDay="
            + "{:0>4}".format(str(year))
            + "{:0>2}".format(str(month))
            + "{:0>2}".format(str(day))
            + "/"
        )
        S3bucket_node3 = glueContext.write_dynamic_frame.from_options(
            frame=azureAuditLog_df_dynf,
            connection_type="s3",
            format = "glueparquet",format_options={"compression":"gzip"},
            connection_options={"path": S3bucket_node3_path, "partitionKeys": []},
            transformation_ctx="S3bucket_node3",
        )


glueContext.forEachBatch(
    frame=dataframe_KinesisStream_node1,
    batch_function=processBatch,
    options={
        "windowSize": "100 seconds",
        "checkpointLocation": args["TempDir"] + "/" + args["JOB_NAME"] + "/checkpoint/",
    },
)
job.commit()
