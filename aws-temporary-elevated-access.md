# AWS Temporary Elevated Access Management (TEAM)
## Overview
### Serverless architecture
- State machine with Lambdas
- DynamoDB
- Cognito
- CloudTrail datalake
### Integrates with Identity Centre to facilitate just in time access requests and approvals
### Define policies for eligble permission sets and approvers
## Functional challenges
### A user group can only have 1 eligibility policy
### Policies are created via clickops and no API
## Security challenges
### Cognito default setting allows self registration
### Difference between revoking access granted and revoking session
## Deployment challenges
### Code Commit is deprecated
- Hosted in a private github repo
- Grant the amplify github app on specific repo
- Create a personal GitHub PAT
- Store PAT in Secrets Manager
- Reference Secret in Cloudformation template
### Cloudformation stack destroy didnt work
- Obscure failure
### Resources are created outside of cloudformation
- S3 bucket
- Cloudwatch logs
- Cognito userpool
### Manual integration
- Cognito to IDP SAML integration
- Identity centre permission sets