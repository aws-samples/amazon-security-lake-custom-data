Event Dossier: Microsoft Azure Generic Event Hub Cloud Activity
An Azure Event Hub Activity Log Event
Description: Translates a DescribeDirectConnectGateways Event to OCSF.
Event References:
[https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema)

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
|`operationName`|`api.operation`|
|`caller`|`actor.user.uid`|
|`callerIpAddress`|`src_endpoint.ip`|
|`identity.claims.name`|`actor.user.name`|
|`time`|`time`|
|`properties.message`|`message`|
|`identity.claims.ver`|`metadata.product.version`|
|`category`|`unmapped.category`|
|`identity.authorization.evidence.role`|`unmapped.role`|
|`identity.authorization.evidence.principalType`|`unmapped.principalType`|
|`location`|`unmapped.location`|

 ### Conditional Mapping:
 - Any fields described within the conditional mappings are subject to dynamic mappings contingent on a conditional evaluation of source data. Fields which fail to meet a particular conditional are assigned a default value from the OCSF schema description.

| OCSF                       | Raw             |
| -------------------------- | ----------------|
|`level`|`severity`|
|`level`|`severity_id`|
|`activity_name`|`category`|
|`activity_id`|`category`|
|`type_uid`|`category`|
|`type_name`|`category`|

# Azure Eventhub Sample Policy Event

            {
                "authorization": {
                    "action": "Microsoft.Resources/checkPolicyCompliance/read",
                    "scope": "/subscriptions/<subscriptionID>"
                },
                "caller": "33a68b9d-63ce-484c-a97e-94aef4c89648",
                "channels": "Operation",
                "claims": {
                    "aud": "https://management.azure.com/",
                    "iss": "https://sts.windows.net/1114444b-7467-4144-a616-e3a5d63e147b/",
                    "iat": "1234567890",
                    "nbf": "1234567890",
                    "exp": "1234567890",
                    "aio": "A3GgTJdwK4vy7Fa7l6DgJC2mI0GX44tML385OpU1Q+z+jaPnFMwB",
                    "appid": "1d78a85d-813d-46f0-b496-dd72f50a3ec0",
                    "appidacr": "2",
                    "http://schemas.microsoft.com/identity/claims/identityprovider": "https://sts.windows.net/1114444b-7467-4144-a616-e3a5d63e147b/",
                    "http://schemas.microsoft.com/identity/claims/objectidentifier": "f409edeb-4d29-44b5-9763-ee9348ad91bb",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "b-24Jf94A3FH2sHWVIFqO3-RSJEiv24Jnif3gj7s",
                    "http://schemas.microsoft.com/identity/claims/tenantid": "1114444b-7467-4144-a616-e3a5d63e147b",
                    "uti": "IdP3SUJGtkGlt7dDQVRPAA",
                    "ver": "1.0"
                },
                "correlationId": "b5768deb-836b-41cc-803e-3f4de2f9e40b",
                "description": "",
                "eventDataId": "d0d36f97-b29c-4cd9-9d3d-ea2b92af3e9d",
                "eventName": {
                    "value": "EndRequest",
                    "localizedValue": "End request"
                },
                "category": {
                    "value": "Policy",
                    "localizedValue": "Policy"
                },
                "eventTimestamp": "2019-01-15T13:19:56.1227642Z",
                "id": "/subscriptions/<subscriptionID>/resourceGroups/myResourceGroup/providers/Microsoft.Sql/servers/contososqlpolicy/events/13bbf75f-36d5-4e66-b693-725267ff21ce/ticks/636831551961227642",
                "level": "Warning",
                "operationId": "04e575f8-48d0-4c43-a8b3-78c4eb01d287",
                "operationName": {
                    "value": "Microsoft.Authorization/policies/audit/action",
                    "localizedValue": "Microsoft.Authorization/policies/audit/action"
                },
                "resourceGroupName": "myResourceGroup",
                "resourceProviderName": {
                    "value": "Microsoft.Sql",
                    "localizedValue": "Microsoft SQL"
                },
                "resourceType": {
                    "value": "Microsoft.Resources/checkPolicyCompliance",
                    "localizedValue": "Microsoft.Resources/checkPolicyCompliance"
                },
                "resourceId": "/subscriptions/<subscriptionID>/resourceGroups/myResourceGroup/providers/Microsoft.Sql/servers/contososqlpolicy",
                "status": {
                    "value": "Succeeded",
                    "localizedValue": "Succeeded"
                },
                "subStatus": {
                    "value": "",
                    "localizedValue": ""
                },
                "submissionTimestamp": "2019-01-15T13:20:17.1077672Z",
                "subscriptionId": "<subscriptionID>",
                "properties": {
                    "isComplianceCheck": "True",
                    "resourceLocation": "westus2",
                    "ancestors": "72f988bf-86f1-41af-91ab-2d7cd011db47",
                    "policies": "[{\"policyDefinitionId\":\"/subscriptions/<subscriptionID>/providers/Microsoft.
                        Authorization/policyDefinitions/5775cdd5-d3d3-47bf-bc55-bb8b61746506/\",\"policyDefiniti
                        onName\":\"5775cdd5-d3d3-47bf-bc55-bb8b61746506\",\"policyDefinitionEffect\":\"Deny\",\"
                        policyAssignmentId\":\"/subscriptions/<subscriptionID>/providers/Microsoft.Authorization
                        /policyAssignments/991a69402a6c484cb0f9b673/\",\"policyAssignmentName\":\"991a69402a6c48
                        4cb0f9b673\",\"policyAssignmentScope\":\"/subscriptions/<subscriptionID>\",\"policyAssig
                        nmentParameters\":{}}]"
                },
                "relatedEvents": []
            }

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

