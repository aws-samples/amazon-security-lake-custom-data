# Azure Eventhub Interesting Fields

            {
                "records": [
                    {
                        "time": "2019-01-21T22:14:26.9792776Z",
                        "resourceId": "/subscriptions/s1/resourceGroups/MSSupportGroup/providers/microsoft.support/supporttickets/123456112305841",
                        "operationName": "microsoft.support/supporttickets/write",
                        "category": "Write",
                        "resultType": "Success",
                        "resultSignature": "Succeeded.Created",
                        "durationMs": 2826,
                        "callerIpAddress": "111.111.111.11",
                        "correlationId": "c776f9f4-36e5-4e0e-809b-c9b3c3fb62a8",
                        "identity": {
                            "authorization": {
                                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-001/providers/Microsoft.Storage/storageAccounts/       msftstorageaccount",
                                "action": "Microsoft.Storage/storageAccounts/listAccountSas/action"
                            },
                            "claims": {
                                "ver": "1.0",
                                "puid": "20030000801A118C",
                                "name": "John Smith"
                            }
                        },
                        "level": "Information",
                        "location": "global",
                        "properties": {
                            "statusCode": "Created",
                            "serviceRequestId": "12345678-8ca0-47ad-9b80-6cde2207f97c"
                        }
                    }
                ]
            }


# Azure EventHub Source Field Table

Schema from storage account and event hubs		
		
When streaming the Azure Activity log to a storage account or event hub, the data follows the resource log schema. The table below provides a mapping of properties from the above schemas to the resource logs schema.		
		
 Important		
		
The format of Activity log data written to a storage account changed to JSON Lines on Nov. 1st, 2018. See Prepare for format change to Azure Monitor resource logs archived to a storage account for details on this format change.		
		
Resource logs schema property	Activity Log REST API schema property	Notes
time	eventTimestamp	
resourceId	resourceId	subscriptionId, resourceType, resourceGroupName are all inferred from the resourceId.
operationName	operationName.value	
category	Part of operation name	Breakout of the operation type - "Write"/"Delete"/"Action"
resultType	status.value	
resultSignature	substatus.value	
resultDescription	description	
durationMs	N/A	Always 0
callerIpAddress	httpRequest.clientIpAddress	
correlationId	correlationId	
identity	claims and authorization properties	
Level	Level	
location	N/A	Location of where the event was processed. This is not the location of the resource, but rather where the event was processed. This property will be removed in a future update.
Properties	properties.eventProperties	
properties.eventCategory	category	If properties.eventCategory is not present, category is "Administrative"
properties.eventName	eventName	
properties.operationId	operationId	
properties.eventProperties	properties	
![image](https://github.com/aws-samples/amazon-security-lake-custom-data/assets/106110648/5e3e9f0c-4daf-4196-8589-afa5d270ddfc)




# Event Field Mappings

            operationName --> api.operation
            identity.authorization.scope --> resources.details
            caller --> actor.user.uid
            identity.claims.ipaddr --> actor.user.name
            time --> time
            level--> severity
            identity.claims.groups --> resources.group_name
            resourceId -->, "resource.owner.uid
            properties.message --> message
            claims.ver --> metadata.product.version
            
# OCSF Field Mappings

            activity_id --> 3/4/5
            activity_name --> Create/Delete/Update
            type_name --> "API Activity: Unknown"
            type_uid --> 300500/300503/300504
            category_name --> "Audit Activity"
            category_uid --> 3
            class_name --> "API Activity"
            class_uid" --> 3005

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

