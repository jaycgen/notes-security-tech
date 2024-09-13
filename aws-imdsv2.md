# IMDSv2
## Why v2?
### Defense in depth against open firewalls
### Open reverse proxies
### SSRF vulnerabilities
## How v2 works?
### Every session starts with a PUT request
### IMDSv2 returns a secret token
### Will not issue session token if X-Forwarded-For header
### Default TTL of 1 protecting against layer 3 misconfiguration
### Sessions last up to 6 hours
### Token is required to access meta-data / instance profile
## Migrate to v2
### Launch instance with ImdsSupport v2.0
### Set IMDSv2 as default
### CloudWatch metric MetadataNoTokenRejected means software needs updating
## Enforce v2
### IAM condition keys
- ec2:MetadataHttpEndpoint
- ec2:MetadataHttpPutResponseHopLimit
- ec2:MetadataHttpTokens
- ec2:RoleDelivery 2.0
### SCP
- Deny ec2:RunInstances Condition StringNotEquals ec2:MetadataHtppTokens: required
## How to find IMDSv1
### CloudWatch metric MetadataNoToken counting v1 calls
### AWS CLI
- aws ec2 describe-instances | grep '"HttpTokens": "optional"'
### AWS Config
- ec2-imdsv2-check