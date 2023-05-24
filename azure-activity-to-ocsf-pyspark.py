import sys
import datetime
import time
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame
from pyspark.sql.functions import *
from pyspark.sql.types import *
from pyspark.sql import DataFrame, Row
from awsglue import DynamicFrame

args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

AWS_REGION_NAME = ""
AWS_ACCOUNT_ID = ""
SECURITY_LAKE_AZURE_STREAM_ARN = ""
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
                 ("time", "string", "time", "string"), 
                 ("resourceId", "string", "unmapped.resourceId", "string"), 
                 ("operationName", "string", "api.operation", "string"), 
                 ("category", "string", "unmapped.category", "string"),
                 ("resultType", "string", "status", "string"), 
                 ("resultSignature", "string", "unmapped.resultSignature", "string"), 
                 ("durationMs", "string", "duration", "string"), 
                 ("callerIpAddress", "string", "src_endpoint.ip", "string"),
                 ("correlationId", "string", "unmapped.correlationId", "string"), 
                 ("identity.authorization.scope", "string", "unmapped.identity.authorization.scope", "string"), 
                 ("identity.authorization.action", "string", "actor.invoked_by", "string"), 
                 ("identity.authorization.evidence.role", "string", "unmapped.identity.authorization.evidence.role", "string"), 
                 ("identity.authorization.evidence.roleAssignmentScope", "string", "unmapped.identity.authorization.evidence.roleAssignmentScope", "string"), 
                 ("identity.authorization.evidence.roleAssignmentId", "string", "unmapped.identity.authorization.evidence.roleAssignmentId", "string"), 
                 ("identity.authorization.evidence.roleDefinitionId", "string", "unmapped.identity.authorization.evidence.roleDefinitionId", "string"), 
                 ("identity.authorization.evidence.principalId", "string", "actor.idp.uid", "string"), 
                 ("identity.authorization.evidence.principalType", "string", "actor.idp.name", "string"), 
                 ("identity.claims.aud", "string", "unmapped.identity.claims.aud", "string"), 
                 ("identity.claims.iss", "string", "unmapped.identity.claims.iss", "string"), 
                 ("identity.claims.iat", "string", "unmapped.identity.claims.iat", "string"), 
                 ("identity.claims.nbf", "string", "unmapped.identity.claims.nbf", "string"), 
                 ("identity.claims.exp", "string", "unmapped.identity.claims.exp", "string"), 
                 ("identity.claims.ver", "string", "unmapped.identity.claims.ver", "string"), 
                 ("identity.claims.http://schemas.microsoft.com/identity/claims/tenantid", "string", "unmapped.identity.claims.http://schemas.microsoft.com/identity/claims/tenantid", "string"), 
                 ("identity.claims.http://schemas.microsoft.com/claims/authnmethodsreferences", "string", "unmapped.identity.claims.http://schemas.microsoft.com/claims/authnmethodsreferences", "string"), 
                 ("identity.claims.http://schemas.microsoft.com/identity/claims/objectidentifier", "string", "unmapped.identity.claims.http://schemas.microsoft.com/identity/claims/objectidentifier", "string"), 
                 ("identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "string", "actor.user.email_addr", "string"), 
                 ("identity.claims.puid", "string", "unmapped.identity.claims.puid", "string"), 
                 ("identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "string", "unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "string"), 
                 ("identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "string", "unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "string"), 
                 ("identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "string", "unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "string"), 
                 ("identity.claims.name", "string", "actor.user.name", "string"), 
                 ("identity.claims.groups", "string", "actor.user.group.name", "string"), 
                 ("identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "string", "unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "string"), 
                 ("identity.claims.appid", "string", "unmapped.identity.claims.appid", "string"), 
                 ("identity.claims.appidacr", "string", "unmapped.identity.claims.appidacr", "string"), 
                 ("identity.claims.http://schemas.microsoft.com/identity/claims/scope", "string", "unmapped.identity.claims.http://schemas.microsoft.com/identity/claims/scope", "string"), 
                 ("identity.claims.http://schemas.microsoft.com/claims/authnclassreference", "string", "unmapped.identity.claims.http://schemas.microsoft.com/claims/authnclassreference", "string"), 
                 ("level", "string", "severity", "string"), 
                 ("properties.statusCode", "string", "unmapped.properties.statusCode", "string"),
                 ("properties.serviceRequestId", "string", "unmapped.properties.serviceRequestId", "string"),
                 ("resourceId", "string", "metadata.product.name", "string"), 
                 ("resourceId", "string", "cloud.provider", "string"), 
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

# Severity	        Description
# Critical	        Events that demand the immediate attention of a system administrator. May indicate that an application or system has failed or stopped responding.
# Error	            Events that indicate a problem, but do not require immediate attention.
# Warning	        Events that provide forewarning of potential problems, although not an actual error. Indicate that a resource is not in an ideal state and may degrade later into showing errors or critical events.
# Informational	E   vents that pass noncritical information to the administrator. Similar to a note that says: "For your information".

        @udf
        def MAP_SEVNAME(source):
            if source == 'Information':
                return "Informational"
            if source == 'Informational':
                return "Informational"
            if source == 'Error':
                return "Low"
            if source == 'Warning':
                return "Medium"
            if source == 'Critical':
                return int(4)
            else:
                return int(99)
            
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
        def MAP_STATID(source):
            if source == 'Unknown':
                return int(0)
            if source == 'Success':
                return int(1)
            if source == 'Failure':
                return int(2)
            else:
                return int(99)
           
        @udf
        def MAP_TIME(string):
            string = string[:-2]
            date_time = datetime.datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%f")
            date_time = datetime.datetime(date_time.year, date_time.month, date_time.day, date_time.hour, date_time.minute, date_time.second)
            date_time = int(time.mktime(date_time.timetuple()))
            return date_time
        
        azureAuditLog_df = azureAuditLog_df.withColumn("category_name", lit("Audit Activity"))\
                                                             .withColumn("category_uid", lit(3))\
                                                             .withColumn("class_name", lit("API Activity"))\
                                                             .withColumn("class_uid", lit(3005))\
                                                             .withColumn("severity", MAP_SEVNAME(col('severity')))\
                                                             .withColumn("severity_id", MAP_SEVID(col('severity')).cast('integer'))\
                                                             .withColumn("activity_name", MAP_AN(col('unmapped.category')))\
                                                             .withColumn("activity_id", MAP_AI(col('unmapped.category')).cast('integer'))\
                                                             .withColumn("type_uid", MAP_TI(col('unmapped.category')).cast('integer'))\
                                                             .withColumn("time", MAP_TIME(col('time')).cast('integer'))\
                                                             .withColumn("status_id", MAP_STATID(col('status')).cast('integer'))\
                                                             .withColumn("type_name", MAP_TN(col('unmapped.category')))
                                                             

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
        
        azureAuditLog_df = azureAuditLog_df.withColumn(
            "actor",
            col("actor").withField(
                "user",
                col("actor.user").withField(
                    "group",
                    col("actor.user.group").withField(
                        "name",
                        split(col('actor.user.group.name'), ",")
                    )
                )
            )
        )
        
        azureAuditLog_df = azureAuditLog_df.withColumn(
            "metadata",
            col("metadata").withField(
                "version",
                lit("1.0.0-rc.2")
            )
        )
        
        a = ["cloud"]
        azureAuditLog_df = azureAuditLog_df.withColumn(
            "metadata",
            col("metadata").withField(
                "profiles",
                array([lit(x) for x in a])
            )
        )

        azureAuditLog_df = azureAuditLog_df.withColumn(
            "cloud",
            col("cloud").withField(
                "provider",
                lit("Microsoft")
            )
        )
        
        azureAuditLog_df_dynf = DynamicFrame.fromDF(azureAuditLog_df, glueContext, "dynamic_frame").repartition(1)
        
        now = datetime.datetime.now()
        year = now.year
        month = now.month
        day = now.day
        region = AWS_REGION_NAME
        account_id = AWS_ACCOUNT_ID

        # Script generated for node S3 bucket
        S3bucket_node3_path = (
             "s3://"+SECURITY_LAKE_BUCKET_NAME+"/ext/AZURE_ACTIVITY"
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
