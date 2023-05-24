# Event Dossier: Microsoft Azure Generic Event Hub Cloud Activity

### An Azure Event Hub Activity Log Event
- **Description**: Translates a Azure Eventhub Activity Event to OCSF.
- **Event References**:
  - https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema


### OCSF Version: 1.0.0-rc.2
  - `class_name`: `API Activity`
  - `class_uid`: `3005`
  - `category_name`: `Audit Activity`
  - `category_uid`: `3`
  - `cloud.provider`: `Microsoft`
  - `metadata.product.name`: `Azure Event Hub Activity`
  - `metadata.product.vendor_name`: `Microsoft`
  - `metadata.profiles`: `[cloud]`

 ### Mapping:
 - This does not reflect any transformations or evaluations of the data. Some data evaluation and transformation will be necessary for a correct representation in OCSF that matches all requirements.

Any fields not present in an explicit mapping will be mapped to the unmapped object. 

| OCSF                       | Raw             |
| -------------------------- | ----------------|
|`time`|`time`|
|`resourceId`|`unmapped.resourceId`|
|`operationName`|`api.operation`|
|`category`|`unmapped.category`|
|`resultType`|`status`|
|`resultSignature`|`unmapped.resultSignature`|
|`durationMs`|`duration`|
|`callerIpAddress`|`src_endpoint.ip`|
|`correlationId`|`unmapped.correlationId`|
|`identity.authorization.scope`|`unmapped.identity.authorization.scope`|
|`identity.authorization.action`|`actor.invoked_by`|
|`identity.authorization.evidence.role`|`unmapped.identity.authorization.evidence.role`|
|`identity.authorization.evidence.roleAssignmentScope`|`unmapped.identity.authorization.evidence.roleAssignmentScope`|
|`identity.authorization.evidence.roleAssignmentId`|`unmapped.identity.authorization.evidence.roleAssignmentId`|
|`identity.authorization.evidence.roleDefinitionId`|`unmapped.identity.authorization.evidence.roleDefinitionId`|
|`identity.authorization.evidence.principalId`|`actor.idp.uid`|
|`identity.authorization.evidence.principalType`|`actor.idp.name`|
|`identity.claims.aud`|`unmapped.identity.claims.aud`|
|`identity.claims.iss`|`unmapped.identity.claims.iss`|
|`identity.claims.iat`|`unmapped.identity.claims.iat`|
|`identity.claims.nbf`|`unmapped.identity.claims.nbf`|
|`identity.claims.exp`|`unmapped.identity.claims.exp`|
|`identity.claims.ver`|`unmapped.identity.claims.ver`|
|`identity.claims.http://schemas.microsoft.com/identity/claims/tenantid`|`unmapped.identity.claims.http://schemas.microsoft.com/identity/claims/tenantid`|
|`identity.claims.http://schemas.microsoft.com/claims/authnmethodsreferences`|`unmapped.identity.claims.http://schemas.microsoft.com/claims/authnmethodsreferences`|
|`identity.claims.http://schemas.microsoft.com/identity/claims/objectidentifier`|`unmapped.identity.claims.http://schemas.microsoft.com/identity/claims/objectidentifier`|
|`identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn`|`actor.user.email_addr`|
|`identity.claims.puid`|`unmapped.identity.claims.puid`|
|`identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`|`unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`|
|`identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`|`unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`|
|`identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`|`unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`|
|`identity.claims.name`|`actor.user.name`|
|`identity.claims.groups`|`actor.user.group.name[]`|
|`identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`|`unmapped.identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`|
|`identity.claims.appid`|`unmapped.identity.claims.appid`|
|`identity.claims.appidacr`|`unmapped.identity.claims.appidacr`|
|`identity.claims.http://schemas.microsoft.com/identity/claims/scope`|`unmapped.identity.claims.http://schemas.microsoft.com/identity/claims/scope`|
|`identity.claims.http://schemas.microsoft.com/claims/authnclassreference`|`unmapped.identity.claims.http://schemas.microsoft.com/claims/authnclassreference`|
|`level`|`severity`|
|`properties.statusCode`|`unmapped.properties.statusCode`|
|`properties.serviceRequestId`|`unmapped.properties.serviceRequestId`|
|`resourceId`|`metadata.product.name`|
|`resourceId`|`cloud.provider`|

 ### Conditional Mapping:
 - Any fields described within the conditional mappings are subject to dynamic mappings contingent on a conditional evaluation of source data. Fields which fail to meet a particular conditional are assigned a default value from the OCSF schema description.

| OCSF                       | Raw             |
| -------------------------- | ----------------|
|`level`|`severity`|
|`level`|`severity_id`|
|`resultType`|`status`|
|`resultType`|`status_id`|
|`activity_name`|`category`|
|`activity_id`|`category`|
|`type_uid`|`category`|
|`type_name`|`category`|



# Azure Eventhub Source Policy Event

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
    
    
# OCSF Transformed Azure Event Hub Policy Event

    {
          "time": 1548108866,
          "unmapped": {
                "resourceId": "/subscriptions/s1/resourceGroups/MSSupportGroup/providers/microsoft.support/supporttickets/123456112305841",
                "category": "Write",
                "resultSignature": "Succeeded.Created",
                "correlationId": "c776f9f4-36e5-4e0e-809b-c9b3c3fb62a8",
                "identity": {
                      "authorization": {
                            "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-001/providers/Microsoft.Storage/storageAccounts/       msftstorageaccount",
                            "evidence": {
                                  "role": "Azure Eventhubs Service Role",
                                  "roleAssignmentScope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                                  "roleAssignmentId": "123abc2a6c314b0ab03a891259123abc",
                                  "roleDefinitionId": "123456789de042a6a64b29b123456789"
                            }
                      },
                      "claims": {
                            "aud": "https://management.core.windows.net/",
                            "iss": "https://sts.windows.net/abcde123-86f1-41af-91ab-abcde1234567/",
                            "iat": "1421876371",
                            "nbf": "1421876371",
                            "exp": "1421880271",
                            "ver": "1.0",
                            "puid": "20030000801A118C",
                            "appid": "12345678-3bq0-49c1-b47d-974e53cbdf3c",
                            "appidacr": "2"
                      }
                },
                "properties": {
                      "statusCode": "Created",
                      "serviceRequestId": "12345678-8ca0-47ad-9b80-6cde2207f97c"
                }
          },
          "api": {
                "operation": "microsoft.support/supporttickets/write"
          },
          "status": "Success",
          "src_endpoint": {
                "ip": "111.111.111.11"
          },
          "actor": {
                "invoked_by": "Microsoft.Storage/storageAccounts/listAccountSas/action",
                "idp": {
                      "uid": "abcdef038c6444c18f1c31311fabcdef",
                      "name": "ServicePrincipal"
                },
                "user": {
                      "name": "John Smith",
                      "group": {
                            "name": [
                                  "12345678-cacfe77c-e058-4712-83qw-f9b08849fd60",
                                  "12345678-4c41-4b23-99d2-d32ce7aa621c",
                                  "12345678-0578-4ea0-9gdc-e66cc564d18c"
                            ]
                      }
                }
          },
          "severity": "Information",
          "metadata": {
                "product": {
                      "name": "Azure",
                      "vendor_name": "Microsoft"
                },
                "version": "1.0.0-rc.2",
                "profiles": [
                      "cloud"
                ]
          },
          "cloud": {
                "provider": "Microsoft"
          },
          "category_name": "Audit Activity",
          "category_uid": 3,
          "class_name": "API Activity",
          "class_uid": 3005,
          "severity_id": 1,
          "activity_name": "Create",
          "activity_id": 1,
          "type_uid": 300501,
          "status_id": 1,
          "type_name": "API Acitvity: API Activity: Create"
    }


# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

