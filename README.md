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

            activity_id --> 0
            activity_name --> Unknown
            type_name --> "API Activity: Unknown"
            type_uid --> 300500
            category_name --> "Audit Activity"
            category_uid --> 3
            class_name --> "API Activity"
            class_uid" --> 3005

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

