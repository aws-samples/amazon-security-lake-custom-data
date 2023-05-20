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
SECURITY_LAKE_BUCKET_NAME = ""

# Script generated for node Kinesis Stream
dataframe_KinesisStream_node1 = glueContext.create_data_frame.from_options(
    connection_type="kinesis",
    connection_options={
        "typeOfData": "kinesis",
        "streamARN": SECURITY_LAKE_AZURE_STREAM_ARN,
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
                 ("caller", "string", "actor.user.uid", "string"), 
                 ("callerIpAddress", "string", "src_endpoint.ip", "string"),
                 ("identity.claims.name", "string", "actor.user.name", "string"),
                 ("time", "string", "time", "string"), 
                 ("level", "string", "severity", "string"), 
                 ("properties.message", "string", "message", "string"),
                 ("identity.claims.ver", "string", "metadata.product.version", "string"),
                 ("identity.claims.ver", "string", "metadata.product.name", "string"),
                 ("category", "string", "unmapped.category", "string"),
                 ("identity.authorization.evidence.role", "string", "unmapped.role", "string"),
                 ("identity.authorization.evidence.principalType", "string", "unmapped.principalType", "string"),
                 ("location", "string", "unmapped.location", "string"),
             ],
            transformation_ctx="ApplyMapping_node2",
        )
        ApplyMapping_node2.printSchema()
        ApplyMapping_node2.show(5)
        
        #add OCSF base fields
        azureAuditLog_df = ApplyMapping_node2.toDF()
        azureAuditLog_df.show()
        
        @udf
        def MAP_AN(source):
            if source == 'Write':
                return 'Create'
            if source == 'Delete':
                return 'Delete'
            if source == 'Action':
                return 'Update'
       
        @udf
        def MAP_AI(source):
            if source == 'Write':
                return int(1)
            if source == 'Delete':
                return int(4)
            if source == 'Action':
                return int(3)
        
        @udf
        def MAP_TN(source):
            if source == 'Write':
                return 'API Acitvity: API Activity: Create'
            if source == 'Delete':
                return 'API Acitvity: API Activity: Delete'
            if source == 'Action':
                return 'API Acitvity: API Activity: Update'
        
        @udf
        def MAP_TI(source):
            if source == 'Write':
                return int(300501)
            if source == 'Delete':
                return int(300504)
            if source == 'Action':
                return int(300503)
        
        @udf
        def MAP_SEVID(source):
            if source == 'Information':
                return int(1)
            if source == 'Informational':
                return int(1)
            if source == 'Low':
                return int(2)
            if source == 'Medium':
                return int(3)
            if source == 'High':
                return int(4)
            if source == 'Critical':
                return int(5)
            if source == 'Fatial':
                return int(6)
            if source == 'Unknown':
                return int(0)
            else:
                return int(99)
           
        @udf
        def MAP_TIME(string):
            string = "2019-01-21T22:14:26.9792776Z"[:-2]
            date_time = datetime.datetime.strptime(string, "%Y-%m-%dT%H:%M:%S")
            return int(((str(time.mktime(date_time.timetuple())).replace(".","")+"00")))
        
        azureAuditLog_df = azureAuditLog_df.withColumn("category_name", lit("Audit Activity"))\
                                                             .withColumn("category_uid", lit(3))\
                                                             .withColumn("class_name", lit("API Activity"))\
                                                             .withColumn("class_uid", lit(3005))\
                                                             .withColumn("severity_id", MAP_SEVID(col('severity')).cast('integer'))\
                                                             .withColumn("activity_name", MAP_AN(col('unmapped.category')))\
                                                             .withColumn("activity_id", MAP_AI(col('unmapped.category')).cast('integer'))\
                                                             .withColumn("type_name", MAP_TN(col('unmapped.category')))\
                                                             .withColumn("type_uid", MAP_TI(col('unmapped.category')).cast('integer'))\
                                                             .withColumn("time", MAP_TIME(col('time')).cast('integer'))

        azureAuditLog_df = azureAuditLog_df.withColumn(
            "metadata",
            col("metadata").withField(
                "product",
                col("metadata.product").withField(
                    "name",
                    lit("Azure")
                )
            )
        )
        
        azureAuditLog_df = azureAuditLog_df.withColumn(
            "metadata",
            col("metadata").withField(
                "product",
                col("metadata.product").withField(
                    "vendor_name",
                    lit("Microsoft")
                )
            )
        )
        
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
             "s3://"+SECURITY_LAKE_BUCKET_NAME+"/ext/AZURE-ACTIVITY"
            + "/region=" 
            + region 
            + "/accountid=" 
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
