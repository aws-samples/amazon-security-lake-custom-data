# My Project

Pending Blog Release

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
            "type_uid --> 300500
            "category_name --> "Audit Activity"
            category_uid --> 3
            class_name --> "API Activity"
            class_uid" --> 3005

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

