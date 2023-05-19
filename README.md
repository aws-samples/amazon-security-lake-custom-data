# My Project

Pending Blog Release

# Azure Event Hub Raw Event

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
                               "action": "Microsoft.Storage/storageAccounts/listAccountSas/action",
                               "evidence": {
                                   "role": "Azure Eventhubs Service Role",
                                   "roleAssignmentScope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                                   "roleAssignmentId": "123abc2a6c314b0ab03a891259123abc",
                                   "roleDefinitionId": "123456789de042a6a64b29b123456789",
                                   "principalId": "abcdef038c6444c18f1c31311fabcdef",
                                   "principalType": "ServicePrincipal"
                               }
                           },
                            "claims": {
                                "aud": "https://management.core.windows.net/",
                                "iss": "https://sts.windows.net/abcde123-86f1-41af-91ab-abcde1234567/",
                                "iat": "1421876371",
                                "nbf": "1421876371",
                                "exp": "1421880271",
                                "ver": "1.0",
                                "http://schemas.microsoft.com/identity/claims/tenantid": "00000000-0000-0000-0000-000000000000",
                                "http://schemas.microsoft.com/claims/authnmethodsreferences": "pwd",
                                "http://schemas.microsoft.com/identity/claims/objectidentifier": "123abc45-8211-44e3-95xq-85137af64708",
                                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "admin@contoso.com",
                                "puid": "20030000801A118C",
                                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "9876543210DKk1YzIY8k0t1_EAPaXoeHyPRn6f413zM",
                                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "John",
                                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "Smith",
                                "name": "John Smith",
                                "groups": "12345678-cacfe77c-e058-4712-83qw-f9b08849fd60,12345678-4c41-4b23-99d2-d32ce7aa621c,12345678-0578-4ea0-9gdc-e66cc564d18c",
                                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": " admin@contoso.com",
                                "appid": "12345678-3bq0-49c1-b47d-974e53cbdf3c",
                                "appidacr": "2",
                                "http://schemas.microsoft.com/identity/claims/scope": "user_impersonation",
                                "http://schemas.microsoft.com/claims/authnclassreference": "1"
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

