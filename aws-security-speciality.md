# AWS Security Speciality
## IAM
### Identity Based Policies
- Version
  - 2012-10-17
- Effect
  - Allow
  - Deny
- Principal
  - Who applied to
- Action
  - service:Foo*
- NotAction
  - Can be used to Allow everything except
  - Can be used to Deny everything except
    - Use to limit to a region
- Resource
  - *
  - ARN
- Condition
  - StringEquals | StringNotEquals
    - case sensitive
    - exact matching
  - StringLike | StringNotLike
    - case sensitive
    - optional partial matching using *
  - Bool
  - DateEquals | DateLessThan
    - eg compare aws:TokenIssueTime
  - IpAddress | NotIpAddress
    - CIDR format
    - eg aws:SourceIp
  - ArnLike | ArnNotLike
  - Null
- Global context conditions
  - aws:RequestedRegion
  - aws:PrincipalArn
    - Who
  - aws:SourceArn
    - for service to service
  - aws:CalledVia
    - athena
    - cloudformation
    - dynamodb
    - kms
  - aws:SourceIp
    - public requester IP
  - aws:VpcSourceIp
    - requester IP via VPC endpoints
  - aws:SourceVpce
    - restrict access to specific VPC Endpoint
  - aws:SourceVpc
    - restrict to specific VPC ID AND must be via VPC Endpoint
  - aws:ResourceTag
    - tags that exist on AWS resources
    - service specific
      - ec2:ResourceTag/Project: DataAnalytics
  - aws:PrincipalTag
    - tags that exist on IAM principal making request
      - aws:PrincipalTag/Department: Data
### Permission Boundaries
- Set maximum permissions
- Constrain high risk actions with conditions
  - Delegate responsibilities with boundaries
  - Enable self service without privesc
  - Attach and Restrict a single principal
  - Test an SCP by applying to an IAM principal
### Resource Based Policies
- S3
  - Allow/deny buckets and objects
  - Grant cross account access
  - Restrict IPs
  - Enforce object owner
  - Enforce SSL
- KMS
  - Allow/deny who can use and manage each key
- SQS
  - Define who can send/receive messages from the queue
  - Grant cross account access
- Lambda
  - Control which services can invoke the function
- SNS
  - Define who can publish/subscribe to topic
  - Integrate with other AWS services or cross account
- Secrets Manager
  - Control which principles can access or manage secrets
  - Integrate with other AWS services or cross account
- ECR
  - Control who can push/pull images from a repository
  - Integrate with other AWS services or cross account
- IAM Roles
  - Define which principles can assume a role
- API Gateway
  - Control who can invoke a REST API
  - Restrict access based on source IP or VPC endpoints
  - Grant cross account access
- Glacier
  - Define Vault lock policies
  - Enforce retention periods
- CloudWatch Logs
  - Control who can put log events into the group
  - Grant cross account access
- Cloudformation
  - Define stack policies to protect resources form unintended updates
- EFS
  - Define file system policies to control acess
  - Enforce read-only access or restrict specific instances
- EventBridge
  - Control which accounts can send/receive event from the bus
- Transfer Family
  - Control access to SFTP/FTP
  - Restrict access based on IP
  - Enforce SSL
- Backup
  - Backup vault access policies control access to backups
### Resource Based Permissions
- CodePipeline
  - Grant cross account access to pipeline resources eg S3 buckets
- CodeBuild
  - Grant permission to access resources in other accounts
### Restrict Resource Policies to Organization
- StringEquals -> aws:PrincipalOrgId: foo
### Cross Account IAM Evaluation
- Must be allowed in both
  - Identity Policy
  - Resource Policy
### ABAC
- Tag examples
  - StringEquals s3:ExistingObjectTag/Foo : aws:PrincipalTag/Foo
  - StringEquals aws:ResourceTag/ProjectName: ${aws:PrincipalTag/ProjectName}
- Scale permissions easily
  - New users and resources automatically inherit access
  - Fewer policies
### Access Analyzer
- Find out which resources shared externally
  - eg S3, IAM, KMS, Lambda, SQS, Secrets Manager
  - Define a Zone of Trust
    - Account or Organization
  - Invariants are reported as Findings
- Policy Validation
  - Grammar and best practises
  - Actionable recommendations
- Policy Generation
  - Generate policy based on activity
    - Uses 90 days of CloudTrail logs
### Access Advisor
- Shows which services accessed by user and when
- Shows which policy enabled the access
### Credential Report
- Creates a CSV
  - Shows when users were created
  - When password last rotated
  - If MFA enabled
  - When access keys last rotated
- Automate access key rotation using AWS Config
  - Trigger if key > 90d
  - Run SSM Automation task
- Only creates a new report after 4h
### IAM Roles for Services
- Common
  - EC2 Instance Roles
  - Lambda Execution Roles
    - Best practise create 1 role per function
    - If event source mapping then Lambda uses role to read event data
    - Consider permissions to write log data
  - CloudFormation roles
- Passing roles
  - Grant iam:PassRole
  - PassRole is not an API call
    - Therefore not in CloudTrail
## Security Token Service (STS)
### Temporary credentials
- Valid between 15min to 1h
  - Can be refreshed for longer
- How to revoke
  - Attach an inline policy
    - Deny *
    - Condition: DateLessThan: aws:TokenIssueTime: {{now}}
  - Doesnt block reauth
### Methods
- AssumeRole
  - Within same account
  - Cross account
- AssumeRoleWithWebIdentity
  - Federation with public IDP
  - Recommend using Cognito instead
- AssumeRoleWithSAML
  - Federation with enterprise IDP using SAML 2.0
- GetFederationToken
  - Get temporary security keys as an IAM user
  - Cannot call IAM operations
- GetSessionToken
  - Get temporary security keys as an IAM user
  - How to use MFA
    - include parameters --serial-number and --token-code
- DecodeAuthorizationMessage
  - Get more information about a Client.UnauthorizedOperation error
- GetAccessKeyInfo
  - Return account ID for specified access Key ID
- GetCallerIdentity
  - Returndetails about the calling user
### STS Versions
- v1
  - Single global endpoint
  - Only supports AWS regions enabled by default
    - Can change setting to all regions
- v2
  - Regional STS endpoints in all regions
    - reduce latency, add redundancy, increase session validity
    - tokens are valid in all regions
### External ID
- Purpose to solve the confused deputy problem
- Condition: StringEquals: sts:ExternalId: 123
- Only allowed if API call passes in ExternalId
  - Deputy should generate the ExternalID
## Directory Service
### Managed Microsoft AD
- Built on AD and Windows Server 2012 R2
  - Creates at least 2 domain controllers in different subnets in specified VPC
  - Requires FQDN + admin account + password
  - Requires necessary ports to be open
- Seamless Domain join for new Windows Server EC2
  - Works across accounts and VPCs
- Establish trust with on-premises AD if required
  - Requires Direct Connect or VPN
  - Choice of trust
    - One way AWS => On-Prem
      - One way incoming so users on premise can be authenticated in AWS
      - Direction of access is opposite to direction of trust
    - One way On-Prem => AWS
      - One way outgoing from on premise means users cannot access resources in AWS
    - Two way AWS <=> On-Prem
- AD Replication manually setup
  - Requires Microsft AD on EC2
- Security
  - no powershell access to instances
  - no direct access via Telnet, SSH, RDP
  - HIPAA + PCIDSS compliant
  - EBS Volumes used are encrypted
- Resilience
  - Automated data replication and daily snapshots
### AD Connector
- Proxy service
  - AWS compatible services to an on premises AD
    - Users are only managed on-prem
    - Auth is proxied over LDAP back to on-prem
  - Not compatible with RDS SQL
  - Requires
    - VPC with at least 2 subnets in different AZ
    - Connection to on premise via VPN or Direct Connect
    - Accounts must have kerberos pre-authentication enabled
### Simple AD
- standalone directory powered by Samba 4
- Security
  - Does not support MFA
  - Does not support trust relationships
  - Does not support LDAPS
### Cloud Directory
- Cloud native directory
- Store 100s of millions of objects
### Trust Relationships
- One-way:incoming
  - Allow users from some other trusted domain to access our resources
- One-way:outgoing
  - Allow our users to access resources in some other domain
- Two-way (Bidirectional)
  - Allow users to access each others resources
## Identity Center
### AuthN
- Enable users logging in outside of AWS to access AWS resources
- SAML 2.0
  - Setup two way trust
    - Download saml-metadata.xml from AWS
    - Register AWS as Service Provider into the IDP
    - IDP generates Metadata XML
      - Register into IAM
    - These Expire and require renewal
      - Error: InvalidIdentityToken (400)
      - aws iam update-saml-provider with new metadata
  - Users access roles using AssumeRoleWithSAML
- Web Identity Federation
  - Without Cognito
    - AssumeRoleWithWebIdentity API
  - With Cognito (Recommended)
    - IDP token exchanged for Cognito token
    - Cognito token exchanged for STS credentials
    - Requires trust between OIDC IDP and AWS
- Custom Identity Broker
  - If IDP not SAML 2.0 compatible
  - Broker is high privileged
    - Handles the credentials
    - Determines the appropriate role
### User Management
- Centralise identities access to multiple AWS accounts
- Works with on premises AD in 2 ways
  - with AWS Microsoft AD
    - requires a two way trust
  - with AD Connector
### Permission Sets
- Map Groups or Claims to policies
  - Auto creates AWS reserved IAM roles
### MFA
- MFA Enforcement
  - S3 MFA Delete
    - Requires bucket versioning
    - Only root account can disable
  - IAM
    - Condition: BoolIfExists: aws:MultiFactorAuthPresent
      - eg Deny if False
    - Condition: NumericLessThan: aws:MultiFactorAuthAge
      - eg Allow if less than 300 s
    - Not AuthZ to perform iam:DeleteVirtualMFADevice
      - If MFA device created but never activated
      - Then must delete existing MFA device by an Admin
      - Recommend policy to only delete MFA if authenticated using MFA
- Types
  - Virtual MFA devices
  - U2F security key
  - Hardware key fob
    - Key fob for Gov.cloud
### Integrates with other applications
- SaaS
  - Salesforce
  - Box
- SAML 2.0
- EC2 Windows instances
## Cognito
### User Pools
- Directory of users
  - Specific to 1 region
- AuthN
  - Simple user/email + password
    - Password Reset
    - Block users if credentials compromised elsewhere
  - MFA
  - Federated login via 3rd party IDP
    - SAML
    - OIDC
    - Social
  - Login returns a JWT
- Email & Phone Number Verification
### Identity Pools
- Federated login via 3rd party IDP
  - SAML
  - OIDC
  - Social
  - works with Cognito User Pools
- Trades token for Temporary AWS credentials
  - Associated with IAM role
    - Trust Policy = Cognito
  - Unauthenticated users can be mapped to an IAM role
  - Partition user access with policy variables
    - Allow s3:ListBucket
      - Condition: StringLike: s3:prefix: ${cognito-identity.amazonaws.com:sub}/*
    - Allow s3:GetObject
      - Resource: arn:aws:s3:::myucket/${cognito-identity.amazonaws.com:sub}/*
    - Allow dynamodb:PutItem
      - Condition: ForAllValues:StringEquals: dynamodb:LeadingKeys: ${cognito-identity.amazonaws.com:sub}
- Use credentials to access AWS services
  - eg S3, DynamoDB, Lambda etc
### aws-verify-jwt library
## Shield
### Scenarios
- Protect and respond to DDOS
  - Optional Shield Advanced
    - Where
      - Elastic IPs
      - Elastic Load Balancers
      - CloudFront
      - Route53
    - Provides
      - 24/7 access to AWS DDos team
      - protection against high AWS fees due to DDoS
    - Costs
      - $3000 per month per organization
    - Shield Advanced CloudWatch Metrics
      - DDoSDetected
      - DDoSAttackBitsPerSecond
      - DDoSAttackPacketsPerSecond
      - DDoSAttackRequestsPerSecond
  - Layer 3 and 4
    - eg SYN/UDP flood
  - Layer 6 and 7
    - eg HTTP Flood
  - Reduce attack surface
  - Plan for scale
    - Transit capacity
      - CDNs
      - Smart DNS
    - Server capacity
  - Differentiate normal and abnormal traffic
## WAF
### Scenarios
- Protect an EC2 from common web exploits
  - Use WAF and managed ACL rules
- Block high volume requests from specific user agent HTTP headers
  - Create a rate based rule
  - Nest string match on HTTP header inside
### Common Integrations
- Cloudfront
- ALB
- API Gateways
- Cognito User Pool
- AppRunner Service
- Verified Access Instance
### Common Management
- Use Firewall Manager to manage WAF across all accounts
- WAF IP Sets
  - Define custom CIDRs
### WebACLs
- Rules
  - Managed rules
    - Rule Groups
      - Baseline Rule Groups
        - CommonRuleSet
        - AdminProtectionRuleSet
      - Use case Specific Rule Groups
        - SQLiRuleSet
        - WindowsRuleSet
        - PHPRuleSet
      - IP Reputation Rule Groups
        - AmazonIpReputationList
        - AnonymousIpList
      - Bot Control Managed Rule Group
        - BotControlRuleSet
    - Use default version or static version
  - Custom rules
    - Regular rules
    - Rate based rules
    - Rule Builder
      - Combination statements
- Functionality
  - Allow
  - Block
  - Count
  - Captcha/challenge
  - Text transformation before inspecting
- Logging
  - Cloudwatch
    - 5MB per second
  - S3
    - 5min interval
  - Kinesis Data Firehose
    - best for highest throughput
  - must have aws-waf-logs prefix
- Capacity
  - Measured in WCUs
    - Max 5000 for a group/acl
    - Charged if > 1500
## Firewall Manager
### Centralise Administration
- WAF
- Shield
- VPC Security Groups
- Use a delegated account in AWS Organizations
## Network Firewall
### Common Scenarios
- Govern ingress
- Govern egress
- Network Firewall can inspect traffic equivalent to an IDS/IPS using Suricata
  - Deep Packet Inspection (DPI) for TLS
    - Integrate with ACM
- Automated detection and response
  - GuardDuty event triggers finding
  - Finding aggregated in Security Hub
  - Finding triggers EventBridge
  - Invokes a Step Function
    - Invokes a Lambda to check if IP in DB
    - Invokes a Lambda to Block traffic
      - Puts IP into Network Firewall
    - Outputs success/failure to SNS
### Components
- Firewall
- Firewall Policy
  - One per firewall
- Firewall rules
  - Supports 1000s rules
  - Filtering options
    - Allow
    - Drop
    - Alert
- Rule Group
  - Stateful options
    - Suricata compatible rule strings
    - Domain list
      - e.g. list like .amazonaws.com
    - Standard stateful rules
      - eg csv with source and destinations
  - Stateless options
### Logging options
- S3
- CloudWatch Logs
- Kinesis Data Firehose
### How to
- Deploy in multiple AZs
  - One subnet per zone
    - Each must have at least 1 available IP
- Update VPC route tables to send incoming/outgoing traffic via firewall
- Tag based
  - Map workloads into Resource Groups
  - Use Network Firewall Rule Groups
## Cloudfront
### Create Cloudfront distribution
- Origin Settings
  - Add a custom header
  - Associate the Origin Access Control
  - Enable Origin Shield
- Cache Behaviour
  - Specify the origin
  - Specify the path pattern
  - Response Headers Policy
    - Enforce secure headers back to client
      - X-Content-Type-Options
        - Protect against MIME sniffing
      - X-Frame-Options
        - Protect against clickjacking
      - X-XSS-Protection
  - Viewer Protocol Policy
    - Require HTTPS from client
    - Or, redirect HTTP to HTTPs
  - Origin Protocol Policy
    - HTTP Only
    - HTTPS Only
    - Match Viewer
  - Define allowed HTTP Methods
  - Cache Policy
    - Allow forwarding headers
      - eg Authorization header
  - Restrict viewer access
    - Trusted signers (Not recommended)
      - Self
      - Specify AWS Accounts
      - Requires using the root user and the console
    - Trusted Key Groups (Recommended)
      - Generate Keypair
        - Add public key to Cloudfront
        - Add Private Key to SecretManager/Parameter Store
        - SSH-2 RSA
        - Base64 PEM encoded
        - 2048bit
- Distribution settings
  - Define an alternative domain
    - Specify the SSL certificate
    - Specify the TLS ciphers
  - Enable logging
  - Custom Errors
  - Root object
- Security
  - Integration with WAF
    - Geo restrictions
  - Field Level Encryption
    - Encrypt data at edge
      - Use asymmetric encryption
    - Up to 10 fields
    - Descope credit card data from Cloudfront + Loadbalancers
### Create Origin Access Control
- Specify S3 origin
- Supports SSE-KMS
  - Key Policy
    - Allow Principal Service -> cloudfront.amazonaws.com
    - Condition -> StringEquals -> SourceArn -> cloudfront distribution
- Require always signing
- Enforces HTTPS to S3 origin by default
### Scenarios
- Generate Signed URL or Signed Cookies using Lambda
  - Generate a Signed URL
    - Choice
      - Canned Policy
      - Custom Policy
      - Optional start time
      - Optional IP restriction
    - Requires
      - Private Key to sign
    - Structure
      - CloudFront Domain Name
      - S3 Resource Path
      - Epoch Time of Expiration
      - Signature Generated via Private Key
      - Cloudfront Public KeyID
    - Libraries
      - generate cloudfront signed url
  - Signing Pre-Reqs
    - Lambda Function IAM role
      - Fetch the Private Key and ID from Parameter Store
- Cognito Auth at edge
  - Use Cognito hosted UI to issue JWT to logged in users
  - Prevent unauthenticated users from downloading SPA source code
  - Use Lambda@Edge to validate JWT or redirect to auth (Viewer Edge)
- Restrict access to ALB to only CloudFront
  - Configure Cloudfront to add a custom HTTP header
  - Configure ALB to only respond if custom header is present
    - Either update ALB listener to verify header
    - Or use AWS WAF filtering rule to check header
      - Autorotate using Secrets Manager + Lambda
  - Restrict source IP in security group
- CloudFront field encryption
  - Uses public key
    - Uploaded into key group
- Caching
  - Point of Presence (POP)
    - Known as edge locations
    - Use SSDs
  - Extra cache = Regional Edge Cache (REC)
    - Use Block Storage
  - Both encrypted at rest automatically
- Improve user experience
## Route 53
### DNS Query Logging
- Log info about public DNS queries received by Route53 Resolver
- Only for public hosted zones
- Only sent to CloudWatch Logs
- Syntax
  - Log format version
  - Query timestamp
  - Hosted Zone ID
  - Query Name
  - Query Type
  - Response Code
  - Query Protocol
  - Edge Location
  - Resolver IP
  - EDNS Client Subnet
### Resolver Query Logging
- Log all DNS Queries
  - Made by resources in VPC
  - Made by on premises using Resolver Inbound Endpoints
  - Using Resolver DNS Firewall
- Output logs to
  - CloudWatch Logs
  - S3
  - Kinesis Data Firehose
- Configurations
  - Shareable using AWS Resource Access Manager
  - JSON document
- Architectures
  - Send all logs to CloudWatch Logs
    - find specific data with CloudWatch Logs Insights
    - get aggregated metrics using CloudWatch Contributor Insights
### Private Hosted Zone
- Allow instances to resolve IPs to a private domain
### Mitigate DNS Spoofing
- DNS Security Extensions (DNSSEC)
  - Works ONLY in public hosted zones
  - Route53 Supports
    - DNSSEC for domain registration
    - DNSSEC for signing
      - Validate a DNS response has not been tampered with
      - Key Signing Key (KSK)
        - Managed by you in KMS
        - Linked to a Customer managed CMK
      - Zone SigningKey (ZSK)
        - Managed by AWS route53
      - Establish chain of trust between hosted zone and parent
        - Parent zone creates Delegation Signer (DS) record
          - Contains a hash of public key used to sign DNS
      - TTL enforced of max 1 week
        - Recommend 1 hour
      - Lower SOA to minimum for 5 mins
      - Monitor for errors using CloudWatch Alarms
        - DNSSECInternalFailure
        - DNSSECKeySigningKeysNeedingAction
## Elastic Load Balancers (ELB)
### Types
- Application Load Balancer (ALB)
  - HTTP/HTTPS/gRPC
    - Layer 7
  - Cannot be associated with an Elastic IP
- Network Load Balancer (NLB)
  - TCP/UDP/TLS
    - Layer 4
  - One static IP per AZ
    - Can be associated with an Elastic IP
  - High performance and lower latency
  - Optional: enable
  - Can attach NLB to security group
    - Need to check NACLs also allow
  - Target groups
    - Supports EC2
    - Supports private IPs including on-prem
    - Supports to an ALB
  - Supports an HTTP health check
- Gateway Load Balancer (GWLB)
  - 3rd party virtual appliances
  - Geneve protocol
    - Layer 3
- Classic Load Balancer (CLB)
### SSL Configuration
- SSL Termination
  - Offload SSL to ELB by installing a certificate from ACM
- Re-encryption
  - Requires a certificate used for both client and server requests
  - Specify instance protocol and port to HTTPS/443
- Passthrough SSL (E2E)
  - Specify a TCP Listener
  - Certificate just required on the backend instance
- Security Policy
  - Combination of SSL protocols, ciphers and server order preferences
  - Frontend
    - Can use a predefined policy
      - ELBSecurityPolicy-TLS
        - specific TLS versions
      - ELBSecurityPolicy-FS
        - Forward secrecy
  - Backend
    - Must use ELBSecurityPolicy-2016-08
### Route using algorithm
- round robin
- least outstanding requests
- session affinity
  - can use application based cookies
    - AWSALBAPP generated cookie
  - can use duration based cookies
    - AWSALB
- flow hash algorithm
  - sticky based on
    - protocol
    - source
    - destination
    - TCP sequence number
## API Gateway
### Key features
- Serverless functionality
- Supports WebSockets
- Supports API Versioning
- Helps handle different environments
- Can offload or enforce AuthN and AuthZ
- Can import Swagger/OpenAPIs
- Can transform & validate requests
- Can cache API responses
### Integrations
- Lambda functions
- HTTP
  - On premise
  - ALB
- REST
- AWS Service
  - Step Function
  - SQS
  - Kinesis Data Streams
### Deployment types
- Edge Optimized (Default)
- Regional
- Private
  - Only within VPC using VPC interface endpoint
    - Can be used to enable Cross Account/VPC
  - Protect with a resource access policy
### Security
- IAM Resource Policy
  - Action -> execute-api:Invoke
  - Resource -> execute-api:/*
  - eg Condition
    - IpAddress -> aws:SourceIp: foo
    - StringNotEquals -> aws:SourceVpce: foo
- Authentication support
  - IAM Roles
  - Cognito
  - Custom Authorizer (via Lambda)
- Throttling
  - 10000 RPS across all APIs
    - 1 overloaded API Gateway can cause other APIs to be throttled
  - HTTP 429 response
  - Can set Stage limit & Method limits
  - Can define Usage Plans to throttle per customer
### Custom domain name with cert in ACM
- If Edge Optimized then certificate must be in us-east-1
- If regional then cert must be in same region
- Must also setup CNAME or alias in Route53
## Certificate Manager
### Public and Private TLS Certificates
- Provision
  - Valid 13 months
  - Must include at least 1 FQDN
- Manage
  - Renewal
  - Cannot download private key
    - Protected with CMK KMS
- Deploy
  - Must prove domain verification
    - Email validation
      - Contacts 3x emails in WHOIS + 5x common system addresses
    - DNS validation
      - CNAME records
      - Programatic using Route53
### Private CA
- Auto renews
- Sends cloudwatch notification
  - Clients can use this to renew
  - DaysToExpiry metric
    - But would require alarm for each certificate
  - AWS_ACM_RENEWAL_STATE_CHANGE
    - Renewed
    - Expired
    - Due to expire
- CA Hierarchies
- Billed per CA per month
### Import certs
- Manual renewal
### Monitor Certificate Expiration
- EventBridge
  - Daily Certificate Expiry
    - Configurable number of days
  - ACM Certificate Approaching Expiration
- AWS Config
  - managed rule
    - acm-certificate-expiration-check
### Integrations
- ELB
  - Subject Alternative Name (SAN)
    - Issue a single certificate for diffferent subdomains
  - Server Name Indication (SNI)
    - Consolidate multiple certificates in a single location
    - Uses input from client to intelligently serve the right certificate
    - Not supported on Gateway Loadbalancer
  - Perfect Forward Secrecy
    - Use unique ephemeral keys for every session
    - Mitigate the impact of an attacker decrypting historic sessions in event of breach
    - Use Elliptic Curve cryptography ECDHE
- Cloudfront
  - Certificates for HTTPS between viewers and CloudFront must be issued in US East (N Virginia)
  - Certificates for HTTPS between Cloudfront and origin can be any region
- Elastic Beanstalk
- API Gateway
- Cloudformation
## KMS
### Scenarios
- Require auto rotation every year
  - Use AWS Managed CMK
- Require rotation with imported key material
  - Use new CMK with imported key material and re-point the alias
- Prevent tampering of ciphertext
  - Add kms:EncryptionContext condition
- Migrate AWS resource encrypted with KMS to another region
  - Use a new CMK in new region
  - For EBS migrate a snapshot
### Key Types
- Symmetric
  - 256bit key (AES)
- Asymmetric
  - RSA (2048) bit key pair
  - ECC key pair
- Multi region keys
  - Replicated
    - Can encrypt in 1 region and decrypt in another
    - only 1 key is primary
  - Same Key ID
  - Example use case
    - DynamoDB Global table with PII
    - Global Aurora
- HMAC keys
  - Generate and verify hash based message codes
### Customer Master Key (CMK)
- Keys are isolated to specific region
- FIPS 140-2 level 3 compliant
  - Since Nov 2023
- CMKs can encrypt max 4KB of data
- Options
  - AWS Managed
    - You cannot manage, rotate or change key policies
    - Auto rotates every 365 days
  - Customer Managed
    - Full control to manage, set policy
    - Optional on-demand rotation
      - Has a limit
    - Optional auto rotation for symmetric
      - 90-2560 days
      - default 365 days
      - backing key changes
      - key ID stays same
  - Automatic rotation
    - Changes the backing key
    - Avoids the key ID, ARN, alias changing
    - EventBridge pattern -> KMS CMK Rotation
### AWS Owned Keys
- Used by AWS Services
- No control or auditing
### Key Material Origin
- AWS_KMS
  - Default: AWS creates and manages in its key store
- Custom Key Store
  - use with CloudHSM
- External
  - Import key material into KMS
    - optional specify expiration date
### Data Encryption Keys (DEK)
- Generated using a CMK
  - Provides the plaintext DEK + Ciphertext DEK + destroys and does not store the DEK
- Can encrypt data larger than 4KB
### Key Alias
- Simplify reference to a Key ID
### API and CLI
- Encrypt
  - Provide the Key ID
  - Provide the plaintext
  - Optional Encryption Context
    - Additional Authenticated Data (AAD)
    - Set of name-value pairs eg password
- Sign
  - Use private asymmetric key to sign a digest
- Decrypt
  - KeyID is required for asymmetric
  - Provide the ciphertext
- GenerateDataKey
  - Used with envelope encryption
    - Encryption on client side
    - Data encrypted with plaintext DEK
    - Encrypted data + encrypted DEK stored in envelope file
    - Use with AWS Encryption SDK
      - Java, Python, C, JavaScript
      - Optimise performance with data key caching
- GenerateDataKeyWIthoutPlaintext
  - Useful for distributed systems
- GenerateRandom
  - Returns a random byte string
### Key Policies
- Resource based policies
  - Explicit allow to user or role
    - Does not require IAM policies as well if inside same account
- Default policy
  - Looks like root principal but it means entities in that account
    - Still subject to IAM policies
  - "Principal": {
    - "AWS": "arn:aws:iam::123456789012:root"
- },
- Example Conditions
  - StringEquals: kms:ViaService
    - Used for specific services eg EC2, SES etc
  - StringEquals: kms:CallerAccount: 12345
    - Must be from account
### Grants
- Simplify complexity without key policies
- Often used for temporary permissions
  - But must be revoked
- Facilitate delegation to AWS services
- Must be specific about Key ID or Key ARN
- --grant-principal
  - Who gets delegated access
- --retiring-principal
  - Optionally who can revoke
- Example Conditions
  - Bool: kms:GrantIsForAWSResource: true
### Key Deletion
- Imported Keys
  - Can set an expiration period
  - Can delete on demand
- Generated Keys
  - Cannot set expiration date
  - Mandatory 7-30d waiting period
  - Can be disabled immediately instead
- Multi region keys
  - All replicas must be deleted first
- Check if still in use
  - log API calls to CloudTrail (denied)
  - push logs to CloudWatch with a Metric Filter
    - * is pending deleting
  - Set alarm to trigger and notify SNS
### KMS API Limits
- Quota
  - 5500, 10000, 30000 req/s based on region
  - Can increase using service quotas console
## CloudHSM
### Dedicated FIPS 14-2 Level 3 hardware
- Good option if using SSE-C
### Clustered across AZs for high availability
### Only accessible via VPC
- CloudHSM Client has to run on an EC2 in the VPC
  - Manage access to keys
  - Manage the users
- Share CloudHSM across accounts
  - Share private subnets via RAM
### Logging
- to CloudTrail
- and on operating system log files
### Integration with AWS Services
- via KMS custom key stored backed by CloudHSM
### Integration with 3rd party services
- SSL/TLS offload
- Windows Server Certificate Authority
- Oracle TDE
- Java Keytool
## SSM Parameter Store
### Hierarchical store for key values
### Integrations
- CloudFormation
  - use {{resolve:ssm:/path/to/parameter.foo}}
- Secrets Manager
  - use /aws/reference/secretsmanager/secret_ID_in_Secrets_Manager
- Service Values
  - e.g. /aws/service/ami-amazon-linux-latest
### Fetch parameters
- Access a decrypted parameter
  - Specify --with-decryption in ssm get-parameters
- Fetch many
  - Use recursive
### Security
- IAM
- Encryption via KMS
  - SecureString
  - Specify the Key ID to use
  - Advanced secure string parameters encrypted with unique data key
### Types
- Standard
  - 10000 allowed
  - 4KB
  - Free
- Advanced
  - 100000
  - 8KB
  - Can use Parameter Policies
    - Assign a TTL to a parameter
    - Examples
      - Notify to expire
      - Notify not changed
  - Charges apply
## Secrets Manager
### Encrypts secrets at rest by default
- Works with KMS
### Rotates secrets
- Uses Lambda rotate functions
  - If inside a VPC
    - Need to add a NAT gateway
    - Or need to configure Secrets Manager service endpoint in the VPC
- Integration with databases
- Uses Staging Labels
  - AWSPENDING
    - Assignment and testing
  - AWSCURRENT
    - new version
  - AWSPREVIOUS
    - old version
### Stores metadata
- Name
- Description
- ARN
- ARN of the KMS Key
- Information about rotation frequency
### Versioned
### Optional resource policy
- Use case for granting multiple users to a secret
### Types
- User Secret
  - Cannot be rotated
  - Used to connect to linked services
  - Relies on master secret to be rotated and propagated
- Master Secret
  - Rotate secrets of linked services
### Enables copying across regions
- Keeps read replicas in sync
### Enables role access across accounts
### Priced per secrets and API calls per month
### Using secrets
- API
  - GetSecretValue
## Organizations
### Consolidated Billing
- IAM Permissions
  - aws-portal:ViewBilling
  - aws-portal:ModifyBilling
  - aws-portal:ModifyPaymentMethods
- Aggregated in master account
- Pricing benefits
### Service Control Policies (SCP)
- Exceptions for accounts before 15 September 2017
  - Cannot prevent root user from tasks
    - Enable/disable MFA
    - Create/Update/Delete X509
    - Create/Update/Delete root access keys
    - Change root user password
- Must have explicit allow from root through each OU
  - eg FullAWSAccess must be assigned alongside specific Deny
- SCP does NOT apply to Management Account
### Control Tower
- Landing zone
  - One landing zone per organisation
- Account Factory
  - Automate provisioning of new accounts
    - Provision baseline defaults
      - VPC default config
      - subnets
      - region
    - Uses AWS Service Catalog
  - Shared Accounts
    - Management account
    - Log archive account
    - Audit account
- Detect and remediate policy violations
  - Detective
    - AWS Config
  - Guardrails
    - Mandatory
      - eg disallow public read to log archive account
    - Strongly recommended
      - eg enable EBS volume encryption
    - Elective
      - common but optional
## Well Architected Framework
### Security
### Reliability
### Performance
### Operational Excellence
- Test at scale
- Automate to experiment easier
### Cost Optimisation
### Sustainability
### AWS Well Architected Tool (WA Tool)
- Perform a review state of applications and cloud workloads
- Example
  - Use AppRegistry module of AWS Service Catalogue
    - Register custom application and associated resources
    - Perform tailored review
## Resource Access Manager
### Only master account can enable sharing with AWS Organizations
- Must be enabled for all features
### Share AWS resources across accounts
- Examples
  - Aurora DB clusters
  - share private subnets across VPCs
  - Codebuild projects
  - transit gateways
  - AMIs
  - Resource Groups
  - Route53 forwarding rules
- CIDR Use Case
  - Provision a VPC customer managed prefix list
  - Add CIDR blocks
  - Share using RAM
### Sharing
- Create a Resource Share
- Specify resources
- Specify accounts
## Service Catalog
### Self service portal of authorised products
- Defined by admins
  - Define products as cloudformation templates
  - Define IAM permissions to access portfolios
    - Launch constraints as an IAM role
- User tasks
  - Launch authorised products
## Logging
### Service Logs
- CloudTrail
  - Trace API Calls
- Config Rules
  - Config and Compliance over time
  - AWS Config Configuration History
    - Must be ON if want to track history
- CloudWatch Logs
  - full data retention
- VPC Flow Logs
  - IP traffic within VPC
- ELB Access Logs
  - metadata of requests via loadbalancers
- CloudFront Logs
  - web distribution access logs
- WAF Logs
  - logging of requests analysed
### Analyse logs
- Store in S3
  - Encrypt logs
  - Control access using IAM + Bucket Policies
  - Archive into Glacier
- Query using Athena
- OpenSearch
  - Successor to Amazon ElasticSearch
  - Enables searching any field even for partial matches
  - Provisioning options for OpenSearch
    - Managed Cluster
    - Serverless Cluster
  - Common patterns
    - DynamoDB -> DynamoDB Streams -> Lambda -> insert OpenSearch
      - Enable partial search
    - CloudWatch Logs -> Subscription Filter -> Lambda -> OpenSearch
    - Kinesis Data Streams -> Kinesis Data Firehose -> OpenSearch
  - Security for OpenSearch
    - Public Access model
      - Access Policies
      - Identity based Policies
      - IP based
    - VPC Access
      - VPC
      - Subnets
      - Security Groups
      - IAM Role
        - Domain Access Policy
          - Broad Access
            - Action: es:*
            - Resource: arn:aws:es:{{region}}:{{account}}:domain/test-domain/*
          - Fine Grain Access
            - Action: es:ESHttpGet
            - Resource: arn:aws:es:{{region}}:{{account}}:domain/test-domain/foo-data/*
## CloudWatch
### Scenarios
- Troubleshoot logs stopped working
  - Check CloudWatch Logs Agent is active
  - Check if EC2 has internet access
  - Check validity of OS Log rotation rules
- Application stopped sending logs
  - Check cloudwatch:putMetricData IAM permission
  - Check connectivity to logs....amazonaws.com
- Need realtime logging across different AWS accounts
  - For a specific use case
    - Create a subscription filter to stream logs cross accounts
    - Use Kinesis or Kinesis Data Firehose to deliver the logs
  - For all logs
    - Configure cross-account observability feature using CloudWatch
### IAM
- There are no CloudWatch ARNS
- Use* as resource in policies
### CloudWatch Dashboard
- Global not regional
### CloudWatch Events
- near real-time stream of system events
- Concepts
  - Events
  - Targets
  - Rules
- Integration options
  - Lambda
  - Step Functions
  - SNS / SQS / Kinesis
### CloudWatch alarms
- Initiate actions based on metric values
- Composite Alarms
  - Complex alarms using AND OR conditions
- Test alarms
  - Use CLI with an alarm state to trigger alarm
- Define threshold for specific metric
  - OK
  - ALARM
  - INSUFFICIENT_DATA
- Targets
  - EC2 Actions
  - Autoscaling
  - SNS
### CloudWatch Logs
- Sources
  - EC2
    - Default
      - CPU utilisation
      - Disk utilisation
      - Network utilisation
    - Custom
      - Memory utilisation
      - Disk swap
      - Disk space
      - Page file
    - Uses /var/log/awslogs.log
  - ECS
  - Lambda
  - VPC Flow Logs
  - API Gateway
  - Log route53 DNS queries
  - Monitor CloudTrail logged events
- Log groups
  - Arbitrary name eg application
- Log stream
  - instances within application, log files, containers
- Metric Filter
  - Can link to Alarms
- Destinations
  - Subscriptions (Real Time)
    - Kinesis Data Streams + Firehose
      - OpenSearch
    - Lambda
  - Subscription Filter (only specific logs)
    - Can go to cross account subscription destination
      - Requires a Destination Access Policy
  - Batch (12hrs)
    - S3
      - CreateExportTask
      - Can take 12hrs
- Define expiration
  - Never expire by default
  - Can choose 24h to 10y
- Security
  - Encryption by default
  - Can specify own KMS keys
- Archive log data
### CloudWatch Agent
- Needs to be installed
  - sudo yum install amazon-cloudwatch-agent
- Configuration
  - Use wizard or JSON file
    - Centralise config using SSM Parameter Store
  - Specify frequency of metrics
  - Specify log paths
  - Config FIle at /opt/aws/amazon-cloudwatch-agent/logs/configuration-validation.log
- Requires IAM
  - logs:CreateLogGroup
  - logs:CreateLogStream
  - logs:PutLogEvents
  - logs:DescribeLogStreams
  - cloudwatch:PutMetricData
  - CloudWatchAgentServerPolicy - managed policy
- Sends logs over internet by default
  - Metrics are prefixed by CWAgent
- Uses Protocols
  - StatsD
    - Supported on Linux and Windows
  - collectd
    - Supported on Linux
  - Uses procstat plugin
    - Collects metrics and monitors system utilisation
### CloudWatch Logs Insights
- Query logs
- View and save to dashboard
### CloudWatch Contributor Insights
- Time series data
  - Identify highest users
## CloudTrail
### Scenarios
- Prevent tampering
  - Log file validation enabled by default
    - Creates a digest file
    - SHA256 hashing with RSA for signing
- Review access within the last 3 months
  - Possible using CloudTrail Console
- Some accounts cant send logs
  - Check Central account S3 bucket policy
  - Check all trails are active
- Where to view events
  - CloudTrail console
  - CloudTrail Lake
    - Run SQL queries on event logs
    - Converts JSON to Aparche ORC format
- Centralisation
  - Multi Region Trail
    - --is-multi-region-trail
  - Organization Trail = Multi Account Trail
    - Must grant cross account permission on S3 bucket
      - s3:GetBucketAcl
      - s3:PutObject
### Types of events
- Management events
- Data events
- Insights events
### Event history
- Visible even without a trail for past 90 days
  - One free copy of management event logs per region
- Delivers events within 15mins typically
### Filters
- Read only events
  - List
  - Describe
  - KMS
    - Encrypt
    - Decrypt
    - GenerateDataKey
- Write only events
  - KMS
    - Disable
    - Delete
### Integration
- CloudTrail sends logs to S3 bucket by default
  - Use Athena to analyse logs in S3 using SQL
    - Can create Athena integration direct from CloudTrail console
  - CloudTrail logs are encrypted with SSE by default
- Configure a trail to send logs to CloudWatch Logs
  - Define a CloudWatch metrics filter
  - Set a threshold to trigger a CloudWatch alarm
  - Connect alarm to notify via service like SNS
- Use EventBridge to react to any type of API call
### Encryption
- defaults to SSE-S3
- Need to use SSE-KMS if required to encrypt and decrypt log files for multiple accounts across all regions
### CloudTrail Insights
- Opt in
- Detect unusual activity on write events
## EventBridge
### Formerly CloudWatch Events
### Event Bus
- AWS Services (Default)
- Partner Event Bus
  - zendesk
  - datadog
- Custom Events
  - custom apps
### Rules
- Rule triggers
  - EventBridge Scheduler
    - Serverless way to create run and manage tasks from a central managed service
      - e.g. run SendCommand API to invoke Systems Manager to execute on a node
  - Filter events (Optional)
  - React to Event Patterns
    - Schedule Cron Jobs
- Trigger destinations
  - Lambda functions
  - SQS/SNS messages
  - Maintenance, Orchestration etc
### Archive
- Can replay archived events
### Schema Registry
- Can download code bindings
### Aggregate across Organization
- Use a dedicated account
- Use a resource policy that allows PutEvents to central ARN
## Athena
### Serverless SQL query service for data in S3
### Performance improvements
- Use columnar data
  - Recommends parquet or ORC
  - Use Glue to convert
- Compress data
  - bzip2, gzip, lz4
- Partition datasets in S3
  - Organise path/partitionColumn=foo
- Use larger files
  - Greater than 128mb
### Federated queries
- Query across data in different sources
- Use Data Source Connectors
  - run on Lambda
### Supports
- CSV
- JSON
- ORC
- Avro
- Parquet
### Pricing $5 per TB of data
### Integrations
- QuickSight for dashboards
  - Troubleshooting
    - requires S3:GetObject
    - might require kms:Decrypt grant
## Kinesis Firehose
### Load streamining data into data stores
### Use cases
- Kinesis + ElasticSearch
  - Unstructured logs into Kinesis Firehose
  - Transform logs in Kinesis using Lambda
  - Send structured logs to ElasticSearch
### Security
- Option to have data automatically encrypted at destination
- Data in transit is NOT automatically encrypted
## Kinesis Data Analytics
### Security
- Encryption of all data in transit enabled by default
  - Uses service managed keys NOT Kms
## Kinesis Data Stream
### Security
- Optional encryption in transit using StartsStreamEncryption API
## ElasticSearch (ES)
### Search analyse and visualise data in real time
### Security
- Compliant
  - PCIDSS
  - NOC
  - ISO
- Eligible
  - HIPAA
- Built in encryption at rest + in transit
## Compromised Resources
### Compromised EC2
- Identify
  - Capture Instance Metadata
- Prioritise
  - Tag instance
- Contain
  - Enable Termination Protection
  - Isolate instance
    - Use a security group
  - Detach from any Auto Scaling
  - Deregister from any ELB
  - Snapshot EBS Volumes
- Eradicate
  - Offline investigation
    - Create a Forensic instance and attach snapshots
  - Online Investigation
    - Snapshot memory or capture network traffic
- Automation
  - Lambda
  - SSM RunCommand
### Compromised S3
- Identify
  - Identify the resource
  - Identify the source
  - Assess if authorised
- Contain
  - S3 Block Public Access
  - S3 Bucket + Identity Policies
  - VPC Endpoints for S3
  - S3 Presigned URLs
  - S3 Access Points
### Compromised ECS Cluster
- Identify
  - Which cluster
  - Which container
- Contain
  - Deny ingress/egress via security groups
  - Stop the container
### Compromised RDS
- Identify
  - Which DB instance
  - Which DB User
  - Review DB Audit logs
- Contain
  - Restrict using Security Groups & NACLs
  - Restrict DB access for user
  - Rotate DB user password
### Compromised IAM credentials
- Identify
  - Identify user
  - Identify activity using CloudTrail
- Contain
  - Attach an inline policy
    - Deny *
    - Condition: DateLessThan: aws:TokenIssueTime: {{now}}
  - Rotate the credential
### Compromised Account
- Contain
  - Delete and Rotate all Access Keys
  - Rotate all IAM passwords
  - Rotate and delete all EC2 key pairs
  - Isolate using an SCP
## Penetration Testing
### Permitted without approval for 8 services
- EC2 + NAT Gateways + ELBs
- RDS + Aurora
- CloudFront
- API Gateways
- Lambda + Lambd@Edge
- Lightsail
- Elastic Beanstalk
### Prohibited
- DoS / DDoS
- Flooding
- DNS Zone Walking via Route53
### How to simulate a DDoS
- Contact AWS DDoS Test Partner
- Allowed on either Protected Resources or Shield Advanced
- Not exceed 20GBps
- Not exceed 5 million packets/s on CloudFront
### Anything else contact AWS
- aws-security-simulated-event@amazon.com
## Inspector
### Automate Security Assessments
- Leverages CVE data
- Outputs a risk score
### Use cases
- For running EC2 Instances
  - Leverages SSM Agent
  - Analyzes OS for vulnerabilities
  - Analyse network reachability issues
- For Container Images pushed to ECR
  - Automate Scans on Push
  - Integrate with CI/CD to get results in pipeline
  - Output reports for compliance
- For Lambda functions
  - Analyzes vulnerabilities in function code
  - Assessment of functions as deployed
### Integrations
- AWS Security Hub
- Amazon EventBridge
### Pricing
- pricing per instances
- pricing per image
  - less for rescans
### Dependencies
- IAM role
  - Managed service role with many perms
### Troubleshoot
- Run Systems Manager
  - Run AWSSupport-TroubleshootManagedInstance
    - Diagnose SSM issue
  - Run Quick Setup
    - Create and attach instance roles
## Guard Duty
### Threat discovery service
- Uses Machine Learning algorithms
- Input data pulled directly from services
  - CloudTrail Events
    - Management events
    - S3 data events
  - VPC Flow Logs
  - DNS Logs
  - Optional features
    - EKS Audit Logs
    - RDS & Aurora
- Findings
  - Severity between 0.1 to 8+
  - Naming convention
    - ThreatPurpose
      - eg Backdoor
    - ResourceTypeAffected
      - eg EC2
    - ThreatFamilyName
      - eg NetworkPortUnusual
    - DetectionMechanism
      - eg TCP
    - Artifact
      - eg DNS
  - Can generate sample findings
  - Types
    - EC2
    - IAM
    - K8s
    - Malware Protection
    - RDS
    - S3
- Features
  - Trusted IP List
    - List/CIDR of public addresses that you trust
    - No findings generated
  - Threat IP List
    - Known malicious IPs
  - Suppression Rules
    - Automatically filter and archive findings
    - Example low value or false positives
- Auto remediation
  - Lambda examples
    - update NACL
    - add WebACL rule
  - Step Function examples
    - Check IP reputation
    - Block Traffic using Network Firewall
- Integrate with Eventbridge
  - Connect to Lambda
  - Connect to SNS
- Can protect against Crytpcurrency attacks
### Manage multiple accounts
- Use AWS Organization
  - Send invitation through GuardDuty
  - Member account can be Delegated Administrator
- Manage findings
- Manage supression rules
- Manage trusted IPs
- Manage threat lists
### Troubleshooting
- Only processes DNS if use default VPC DNS resolver
- Ensure GuardDuty is not suspended or disabled
- Best practise to enable even in Regions you dont use
## Detective
### Service to get to the root cause of issues
- Uses data
  - VPC Flow Logs
  - CloudTrail
  - GuardDuty
- In response to Finding
## Security Hub
### Central Security tool dashboard
- Aggregates alerts across services
  - Config
  - GuardDuty
  - Inspector
  - Macie
  - IAM Access Analyzer
### Checks / Actions
- Relies on AWS Config to be enabled
- Managed Checks
  - Examples
    - CIS AWS Foundations
    - AWS Foundational Security Best Practises
- Custom Actions
  - Example
    - Process a Macie Finding from a member account
    - Trigger EventBridge
    - Invoke a Lambda
    - Remediate the S3 bucket
    - Mark Finding as Resolved
### Findings
- Central format ASFF
- Findings usual 5min SLA
- Receive Findings
  - Audit Manager
  - AWS ChatBot
  - Trusted Advisor
  - SSM Explorer and OpsCenter
  - Generates Events in EventBridge
  - Investigate issues
    - Use Detective
- Process Findings
  - Set a workflow status
  - Deleted after 90days
  - Insights
    - Managed Insights
      - Cannot edit
    - Custom Insights
      - eg track critical
### Integrations
- 3rd party Senders
  - AlertLogic
  - Aqua
- 3rd party Receivers
  - Atlassian
  - Fireeye
### Cross Region Aggregation
### AWS Organization integration
- Can delegate administrator for Security Hub
## Systems Manager
### Services
- Resource Groups
  - Use tags
    - Better to have too many tags
    - Examples
      - Name
      - Environment
      - Automation
      - Cost Allocation
      - Security
  - Regional level
- Operations Management
  - OpsCenter
  - Incident Manager
- Shared Resources
  - Documents
- Change Management
  - Automation
  - Maintenance Windows
    - Define when to perform actions
    - Schedule
    - Duration
    - Set of registered instances + tasks
    - Can apply a rate limit
- Application Management
  - Parameter Store
  - AppConfig
- Node Management
  - Session Manager
    - Start a secure shell on EC2
    - Does not require SSH access, bastions or SSH keys
    - Supports Linux MacOS Windows
    - Session logs can be sent to S3 or CloudWatch Logs
    - CloudTrail can intercept StartSession events
    - Requires IAM
      - Can use tags to restrict access
      - Can restrict specific commands if needed
  - Run Command
  - Patch Manager
    - Patch Baselines
      - Type
        - Pre-defined Patch Baseline
          - aws-RunPatchBaseline
        - Custom
      - Rule for auto-approving patches after release
      - List of approved or rejected patches
    - Patch Group
      - Associates instances with a Patch Baseline
    - On demand or schedule
    - Generates a patch compliance report
  - Inventory
    - Collect metadata from managed instances
    - Specify frequency
    - ResourceSync
      - Collate detailed information across accounts in S3
  - State Manager
    - Apply state to instances
    - State Manager Association
      - Define the target state
    - Specify a schedule to apply config
      - Uses SSM Documents
  - Fleet Manager
    - Shows nodes under management
### Documents
- Define parameters and actions
- Use AWS Managed Documents
- Create Custom Document
  - JSON or YAML
- Apply Documents
  - RunCommand
    - Execute a document across instances
    - Rate Control + Error Control
    - Integrated with IAM + CloudTrail
    - Can be invoked with EventBridge
  - Automations (Runbooks)
    - Execute commands against resources
    - Triggers
      - Manual
        - Console, CLI, SDK
      - EventBridge
      - Maintenance Window
      - AWS Config for rules remediation
    - Examples
      - Restart EC2 Instance
### Integrations
- CloudWatch metrics
- AWS Config
### Supports
- AWS
- OnPrem
- Linux
- Windows
### Dependencies
- SSM Agent
  - Preinstalled
    - Amazon Linux AMIs
    - Some Ubuntu AMIs
  - Manual Install
- IAM Instance Profile
  - AmazonSSMManagedInstanceCore
### Pricing
- Free
## Artifact
### Self contained repository of AWS own security and compliance reports
### Artifact Reports
- ISO
- Service Organization Control (SOC)
- PCI-DSS
### Artifact Agreements
- Business Associate Addendum (BAA)
- HIPAA
## Verified Access
### Trust providers
- Identity based
  - Identity Center
  - OIDC IDP
- Device based
  - Crowdstrike
  - Jamf
  - Jump cloud
### Verified Access Endpoint
- Integrations
  - Protection
    - WAF
  - Logs
    - CloudWatch
    - S3
    - KDF
  - Downstream
    - ALB
    - ENI
### Common Scenarios
- Avoid needing a VPN
- Centralise authentication for corporate applications
## Glue
### Fully managed ETL service
### Glue streaming ETL runs in Apache Spark serverless environment
### Job Bookmarking
- Keep track of where a job left off in case it was interrupted
### Glue Data Crawler
- auto discover data and store metadata
### Glue Data Catalog
- Resource based policies
  - Allow principles from other accounts
- easily search and access data in other data stores
  - Search in S3 or other services
### Glue Studio
- visually create, run, monitor ETL workflows
## Workspaces
### IP Access Control Groups
- Similar to Security Groups but for workspaces
- Specify the authorized IPs/CIDR to connect from
### Certificate based authentication
- Limit access to trusted devices
- Windows
- MacOS
- Android
## Macie
### Machine learning to discover, classify and protect sensitive data
- PII
- PHI
- API keys/secrets
### Data source
- Cloudtrail event logs and errors
- S3 objects
### Compatible with multi account strategy
- Send invite to account via Macie
- Supports delegated Administrator via AWS Org
### Automatic classification
- Content Type
- File Extension
- Theme
- Regex
### Data Identifiers
- Basic
  - Managed by AWS
    - Credit card numbers
    - AWS credentials
  - Custom data identifier
    - Set of criteria
    - Regex
    - Keywords
    - Proximity rule
- Predictive
  - Deviations from normal behaviour
### Findings
- Sensitive data discovery result
  - Can be stored into S3
  - Kept for 90 days
- Suppression rules
  - Attribute based filter to auto archive findings
- Finding Types
  - Policy Findings
    - eg encryption is disabled
  - Sensitive Data findings
### Notify
- Output to EventBridge
## Config
### Scenarios
- Detect and auto respond to enable VPC Flow Logs
  - AWS Config rule to detect
  - EventBridge rule to trigger
  - Lambda function to action
- Detect and auto respond to enable CloudTrail
- Detect if EC2 instances use approved AMIs
  - approved-amis-by-id managed rule in AWS Config
  - Use CloudWatch Alarms for notification
- Detect and auto respond to remediate security groups that allow inbound 0.0.0.0/0 CIDR
  - Create an AWS config rule to detect
  - vpc-sg-open-only-to-authorized-ports
  - Associate a lambda function to replace with company CIDR
- Detect any API key for root user
  - AWS Config rule to track create-api-key command by root user
- Detect if Internet Gateway added to unauthorized VPC
### Configuration Scope
- Resources to record
  - All or some
- Delivery method
  - S3
### Rules
- Managed by AWS
- Custom
  - Runs in Lambda
### Remediations
- SSM Automation Documents
- Custom Automation Documents
  - eg invoke Lambda
- Remediation retries option
  - max 5
### Notifications
- EventBridge
  - notify or trigger Remediation
- SNS
### Per region service
- AWS Config Aggregators
  - centralise data collection across regions and accounts
  - designate 1 account as Aggregator
  - can still ONLY create rules inside each account
    - use Cloudformation Stacksets to deploy multiple
## Cloudformation
### Template sources
- S3
- Git sync
### Changesets
- Add, update, replace
### Service Role
- requires IAM PassRole
### Stack policies
- Define what updates are allowed/denied on resources
- Specify an explicit allow to change resources
### TerminationProtection
- Requires activation
### Drift
- Detect out of bound changes
  - Needs to be triggered
### CloudFormationGuard
- cfn-guard cli tool
  - eg use as part of CICD
- Define policies as code using declarative DSL
- Builtin testing framework to verify rules work
### Dynamic references
- ssm
- ssm-secure
  - Password: '{{resolve:ssm-secure:SomeUserPassword}}'
- secretsmanager
  - Password: 'resolve:secretsmanager:MyKey:SecretString:myvalue}}'
## EC2
### Keypairs
- Linux
  - Control SSH access to instance
  - Public key stored in .ssh/authorized_keys
- Windows
  - Decrypt the administrator password
- Generation
  - AWS Generated
    - Private key shown but not stored
    - Cannot recover lost key
  - Client Generated
    - Only upload public key
  - Support
    - ED25519
    - 2048bit SSH-2 RSA
- Deletion
  - Removing from console does not remove it from EC2
- Remediating Exposed Keys
  - Delete key from .ssh/authorized_keys
  - Automate using SSM RunCommand
- Fix Lost keypair
  - Fix using EC2 User Data
    - Gets run on every start
    - Instruct it to add a public key
  - Fix using Systems Manager
    - Requires SSM Agent + IAM Role
    - Use AWSSupport-ResetAccess automation document
    - Read the private key out of Parameter Store
  - Fix using EC2 Instance Connect
  - Fix using EBS Volume Swap
    - Stop original instance
    - Detach EBS root volume
    - Attach volume as secondary volume
    - Change .ssh/authorized_keys
    - Re-attach volume and reboot
- Fix Lost Password (Windows)
  - Fix using EC2Launch v2
    - Attach volume to temporary instance
    - Delete %programData%/Amazon/EC2Launch/state/.run-once
    - Re-attach volume
    - Set a new password
  - Fix using EC2Config
    - for Windows AMIs before Windows Server 2016
    - Attach volume to temporary instance
    - Modify ProgramFiles\Amazon\Ec2ConfigService\Settings\config.xml
    - Set EC2SetPassword to Enabled
    - Re-attach volume
  - Fix using EC2Launch
    - for AMIs before EC2Launch v2
    - Use temporary instance
    - Download and install EC2RescueTool
  - Fix using Systems Manager
    - Requires SSM Agent installed
    - Option to run AWSSupport-RunEC2RescueForWindowsTool
      - Installs and runs EC2RescueTool
    - Run AWS-RunPowerShellScript command
      - Command: net user Administrator Password123
- Alternatively use Systems Manager Session Manager
  - Keeps history of commands run during session
### EC2 Instance Connect
- Browser Based SSH
- Requires EC2 Instance Connect Agent on EC2
- Temporary public key with one time use pushed to Instance Metadata
  - Agent fetches key from metadata
- Requires Security Group to allow inbound connection from AWS EC2 Instance Connect service
  - Use IP Prefix
- Connections are logged in CloudTrail
### EC2 Serial Console
- Troubleshoot issues
  - Boot/reboot issues
  - Network configuration
- Works with Nitro based EC2
  - Disabled by default
- Must setup OS User + Password
- 1 active session
### EC2Rescue Tool
- Diagnose common issues
- Linux
  - Collect system utilisation reports
  - Collect logs and details
  - Detect system problems
  - Remediate configurations
- Windows
  - Troubleshoot intance connectivity
  - Fix OS Boot Issues
  - Gather OS Logs and config files
  - Troubleshoot common OS issues
  - Perform a restore
### Build AMI images
- IAM policies
  - EC2InstanceProfileForImageBuilder
  - EC2InstanceProfileForImageBuilderECRContainerBuilds
  - AmazonSSMManagedInstanceCore
- EC2 Image Builder
  - Use a recipe to define
    - Source AMI
      - Source O/S
        - amazon linux 2
          - user = ec2-user
    - Source Docker
    - Specify components
    - Specify tests
    - Define infrastructure config
      - IAM Role and policies
    - Define distribution to regions
  - Creates instance and applies software
  - Creates new AMI
  - Creates and runs tests on test ec2 instance
  - Can be triggered on schedule
### EC2 Instance Metadata Service (IMDS)
- 169.254.169.254
  - /latest/meta-data
    - stored in key-value pairs
    - /
      - ami-id
      - instance-id
      - network
      - hostname
      - placement
      - security-groups
      - tags/instance
      - iam
        - instanceProfileArn
        - security-credentials/role-name
          - temporary credentials
- Restrict access
  - local firewall
    - eg iptables
  - Turn off via Console/AWS CLI
    - using HttpEndpoint=disabled
- v1
  - Track usage
    - CloudWatch Metric
      - MetadataNoToken >0
    - AWS CLI
      - aws ec2 describe-instances | grep '"HttpTokens": "optional"'
    - AWS Config
      - ec2-imdsv2-check
- v2
  - Why v2?
    - Defense in depth against open firewalls
    - Open reverse proxies
    - SSRF vulnerabilities
  - How v2 works?
    - Get Session Token
      - Requires headers
        - X-aws-ec2-metadata-token-ttl-seconds: 21600
      - Requires PUT
        - http://169.254.169.254/latest/api/token
    - Will not issue session token if X-Forwarded-For header
    - Use Session Token
      - Requires headers
        - X-aws-ec2-metadata-token: $TOKEN
    - Default TTL of 1 protecting against layer 3 misconfiguration
    - Sessions last up to 6 hours
  - Enforce IMDSv2
    - IAM condition keys
      - ec2:MetadataHttpEndpoint
      - ec2:MetadataHttpPutResponseHopLimit
      - ec2:MetadataHttpTokens
      - Deny -> Condition: NumericLessThan: ec2:RoleDelivery: 2.0
    - SCP
      - Deny ec2:RunInstances Condition StringNotEquals ec2:MetadataHtppTokens: required
### Auto Scaling Instance Refresh
- Goal to update launch templates and re-create instances
- Invoke StartInstanceRefresh API
  - Specify min. healthy percentage
  - Triggers rolling refresh
## Databases
### RDS + Aurora security
- At-rest encryption
  - must be defined at launch
- In-flight encryption
  - TLS ready by default
  - Use AWS TLS root cert on client
- IAM Authentication
  - Supported by RDS
    - MariaDB
    - PostgreSQL
    - MySQL
  - Auth token lifetime 15min before starting session
- How to encrypt an unencrypted snapshot
  - Restore snapshot to cluster and specify KMS key
  - Then create encrypted snapshot of encrypted cluster
### Redshift Security
- Superusers
  - have same permissions as DB owners
  - e.g. admin user
  - must be a superuser to create a superuser
- Users
  - canonly be created and dropped by a superuser
  - can own databases and database objects eg tables
  - can grant permissions on objects to other users, groups and schemas
- AuthN
  - IAM
    - GetClusterCredentials API
      - gives temporary credentials
    - GetClusterCredentials Autocreate
      - create a new DB user each time
  - User/Password
### DynamoDB
- TTL
  - Automatically delete items after an expiry
    - eg a session data table
  - Must be a number data type with unix epoch timestamp
- Encryption options
  - DynamoDB Encryption Client
    - SDK that provides end to end encryption
    - Uses signing to protect against tampering
    - Only encrypts selected attribute values
  - Server Side Encryption
    - Default
      - Free
      - Owned by Amazon
    - Customer managed CMK
    - AWS Managed CMK
## Nitro Enclaves
### Process highly sensitive data in isolated compute
- Secure private keys
- Multi party computation
- credit cards
- PII
- Health information
### Runs on EC2 with EnclaveOptions true
- Isolated
  - No persistent storage
  - No interactive access
  - No external networking
    - use Virtual Sockets (VSock)
      - communicates with parent EC2
    - encrypted tunnels to services like KMS
### Orchestration
- AWS Nitro Enclave CLI
- enclavectl
  - automates steps
    - build enclave image file (EIF)
    - package eif into docker image
    - --prepare-only
      - generate a deployment specification yaml file
      - deploy it with kubectl apply
    - enclavectl run
      - can auto generate and deploy
- Nitro Enclaves device driver for EKS/K8s
  - plugin runs as daemonset
### Integrity
- Cryptographic Attestation
  - Only run trusted code in Enclave
  - Generates checksums of the environment
  - eg Use
    - KMS Key policy with conditions
      - "kms:RecipientAttestation:PCR0":"EXAMPLE8abcd"
- Measurements
  - from build
    - PCR0
      - contents of EIF
    - PCR1
      - linux kernel and bootstrap
    - PCR2
      - application
    - PCR8
      - enclave image signing cert
        - eg openssl
  - from runtime
    - PCR3
      - IAM role assigned to parent
    - PCR4
      - InstanceID of parent
## Fargate
### Serverless compute engine
- Works with EKS and ECS
- Requires no cluster capacity management
  - Specify CPU and memory at the task level
### Logs
- Supports
  - awslogs
  - splunk
  - fluentd
### Network
- awsvpc mode
### Fargate Spot
- runs on lower cost instances
## Elastic container registry (ECR)
### Store and manage docker images
### Options
- Private
- Public
### Backend
- images stored on S3
### Security
- Supports vulnerability scanning
  - Basic scanning
    - Uses CVE database
    - Configure scan on push or manually
  - Advanced Scanning
    - Uses Amazon Inspector
      - Findings go to EventBridge
    - Automated and continuous scanning
    - Scan both OS and app packages
- Cross account sharing
  - Use a resource policy to grant
  - docker login --password-stdin AccountID.dkr.ecr.region.amazonaws.com
- Supports KMS with envelope encryption
  - Encryption must be set at creation
  - Uses KMS grants
- Troubleshooting
  - Authenticated to wrong region
  - AuthN to a repository dont have permissions for
  - AuthN token has expired
## Elastic Container Service (ECS)
### Inject secrets into containers as environment variables
- Can use SSM Parameter Store
- Can use Secrets Manager
- Reference in the container definition
## Elastic Kubernetes Service (EKS)
### Logging
- Default event TTL is 60mins
- Events must be sent to CloudWatch logs to be retained longer
- Node logs
  - audit logs
  - controller logs
  - diagnostic logs
- Pod events
  - application logs
## Simple Email Service (SES)
### Fully managed service
- Use cases
  - Transactional
  - Marketing
  - Bulk email
### Inbound and Outbound service
- Send email via
  - AWS Console
  - AWS APIs
  - SMTP
### Features
- Reputation dashboard
- Performance insights
  - Email deliveries
  - Bounces
  - Feedback loop
- Configuration Sets
  - Customise and analyse send events
  - Event destinations
    - Kinesis Data Firehose
      - Metrics for each email
    - SNS
      - immediate feedback on bounce
  - IP pool management
    - send particular types of emails
- Anti spam feedback
### Security
- DomainKeys Identified Mail (DKIM)
- Sender Policy Framework (SPF)
## IoT Core and MQTT
### IoT Core supports device connections that use the MQTT protocol and MQTT over WSS
### Device SDKs support the authentication protocols that the AWS IOT services require
### iot:Connection.Thing.ThingName
- resolves to the name of the thing in IoT Core registry
### granting iot:Connect with client/${iot:ClientId}
- Allows a device to connect with its unique ID
### IoT device defender
- Audit cloud side configurations
- Detect device behaviour anomalies
## VPC
### Subnets
- Sizing
  - Created in 1 specific AZ and cannot be changed
    - General recommendation to have 3+
- Allocated a CIDR
  - Subset of the VPC CIDR
  - Cannot overlap with other subnets in same VPC
  - Always 5 reserved IPs
    - First 4
      - Network address
      - Reserved for VPC router
      - Reserved for DNS
      - Reserved for future
    - Last 1
      - Broadcast address
- Has 1 route table
  - Subnet is automatically associated with main route table for the VPC
### Network ACLs
- Subnet layer
  - Can be associated with 1 or more
- Allow or deny
- Evaluated in order lowest number first
- Default
  - allows all inbound and outbound
- Custom
  - denies all inbound and outbound until add rules
- Stateless
  - Remember rules for ephemeral ports 1024-65535
    - Windows
      - 49152 - 65535
    - Linux
      - 32768 - 60999
  - Changes immediately take effect
### Security Groups
- Instance level
- Only allow rules
- Stateful
  - Changes do not disrupt existing connections
- Prefix Lists
  - Customer Managed Prefix List
    - Can share across accounts
  - AWS Managed Prefix List
    - Help represent AWS services instead of via IP range
      - Add DestintationPredixListId
    - Cannot Modify
### Internet Gateway (IGW)
- Supports bidirectional internet access
  - Enables inbound access from internet for services with public IP
- Regionally resilient
  - Covers all AZs in the VPC
- A VPC has 0 or 1 IGW
### NAT Gateway
- Enables private IPs to masquerade behind public IP
  - Does not work with IPv6
  - Facilitates outbound internet access
- AZ Resilient service
- Scales to 45GBps
- Needs to run from public subnet
  - Associated with an Elastic IP
### DNS Resolution
- enableDnsSupport
  - Defaults to True
- Decides if DNS resolution from Route 53 Resolver is supported for the VPC
  - Queries using either
    - 169.254.169.253
    - base of the VPC IPv4 range plus two (.2)
- enableDnsHostnames
  - Default to True for default VPC
  - Default to False for new VPCs
  - Assigns public hostname to EC2 instance if has public IPv4
### Reachability Analyzer
- Feature to perform network diagnostics between 2 resources
- Source/destination
  - EC2 instance
  - Network Interface
  - Subnet VPC peering connection
  - VPN connection
  - Transit gateway connection
### VPC Endpoint Interface
- Elastic network interface
  - Private IP
    - Supports IPv4
  - One subnet per AZ
- Requires DNS to be enabled
- Entrypoint for traffic to supported service
- Can be accessed via DirectConnect/VPN
### VPC Endpoint Gateway
- Supports
  - DynamoDB
  - S3
- Target for specific route in route table
  - Same region only
  - Scoped to specific VPC
- Requires
  - DNS Support is Enabled
  - Outbound rules of Security Groups allow traffic to S3
- Multiple configurations
  - Multi gateway endpoints in single VPC
  - Multi gateway endpoints for single service
    - But needs different route tables
### AWS PrivateLink
- VPC Endpoint Services
- Most secure & scalable way to expose a service to 1000s of VPC
  - own or other accounts
- Does NOT require
  - VPC peering
  - internet gateway
  - NAT
  - route tables
- Example use case
  - Privately expose EC2 application to customer VPC
    - Service VPC with Application Service + Network Load Balancer
    - AWS PrivateLink to ENI in Customer VPC
    - IF NLB + ENIs in multiple AZ then fault tolerant
  - Privately expose ECS application to customer VPC
    - Service VPC with Application Service + ALB + NLB
    - AWS PrivateLink to ENI in Customer VPC
    - IF NLB + ENIs in multiple AZ then fault tolerant
### Security
- Optional VPC endpoint access policy
  - Specifies access to the service to which you are connecting
  - Can be attached to both Interface Endpoint + Gateway Endpoint
  - Policy Example
    - Condition StringEquals aws:sourceVpce: foo
    - Condition IpAddress aws:SourceIp: bar
    - Resource aws:s3:::bucketfoo
  - Use Case Example
    - CodeDeploy API
      - com.amazonaws.region.codedeploy
    - CodeDeploy Agent
      - can be required for EC2
      - com.amazonaws.region.codedeploy-commands-secure
    - SecretsManager
      - can be required for Lambdas
    - Private connection to EC2 via SSM
      - Security Group
        - Allow outbound 443 to VPC endpoint SG and attach to EC2 SG
        - Allow inbound port 443 from VPC CIDR and attach to VPC endpoint SG
      - SSM Service
        - Allow inbound 443
        - com.amazonaws.region.ssm
      - SSM Session Manager
        - com.amazonaws.region.ssmmessages
        - Allow inbound 443
      - SSM Commands
        - com.amazonaws.region.ec2messages
        - Allow inbound 443
      - Optional
        - CloudWatch Logs
        - KMS Encryption
        - S3 (Store Logs)
    - Private connection to Patch Manager
      - Security Group
        - Allow outbound 443
      - SSM Service
        - Allow inbound 443
        - com.amazonaws.region.ssm
      - SSM Commands
        - com.amazonaws.region.ec2messages
        - Allow inbound 443
      - S3 (Get Patches)
        - Allow AWS buckets
          - arn:aws:s3:::patch-baseline-snapshot-region/*
          - arn:aws:s3:::aws-ssm-region/*
      - Optional
        - CloudWatch Logs
    - Private REST API Gateway
      - API Gateway
        - com.amazonaws.region.execute-api
        - Combine with API IAM Resource Policy
          - Restrict aws:SourceVpc
- Bastion Hosts
  - Place in public subnet
  - Enable external inbound SSH via Security Group
  - Enable private subnet hosts to have inbound SSH from Bastion SG
### Gateway Load Balancer Endpoint
- Intercept traffic and route to service
- Configuration
  - Choose VPC and subnet
    - Cannot change subnet later
  - Endpoint network interface
    - Private IP
      - IPv4 only
### VPC Flow Logs
- Capture info about IP traffic going into interfaces
  - VPC Flow Logs
  - Subnet flow logs
  - ENI flow logs
- Monitor and troubleshoot connectivity issues
  - Also covers AWS managed interfaces
    - ELB
    - RDS
    - Transit gateway
    - NAT Gateway etc
  - Use case
    - Identify if NACL or SG blocking traffic
      - Differentiate if Inbound ACCEPT + Outbound REJECT = NACL
  - Syntax
    - Version
    - AccountID
    - Interface ID
    - Source Address
    - Destination Address
    - Source Port
    - Destination Port
    - Protocol
    - Packets
    - Bytes
    - Start
    - End
    - Action
      - Accept
      - Reject
    - Log Status
- Integration options
  - S3
    - Athena to query
      - Requires an S3 bucket to store result
      - Create Table using specific schema for vpc_flow_logs
        - Alter table to add partition by DATE
    - Quicksight to visualise
    - Requires permissions
      - S3 bucket policy
        - Auto created to allow VPC
  - Cloudwatch logs
    - Cloudwatch insights to query
      - eg Top 10 IP Addressess
    - CloudWatch Metric Filter + Alarm
      - eg unexpected threshold of SSH / RDP traffic
    - Requires permissions
      - IAM Role
        - Custom trust policy
          - Principal -> Service -> vpc-flow-logs.amazonaws.com
        - CloudWatchLogsFullAccess
    - Requires a Log Group
      - Specify retention period
  - Kinesis data firehose
- Traffic Not covered
  - To Amazon DNS Server
  - For Amazon Windows License activation
  - To EC2 instance metadata
    - 169.254.169.254
  - To / From Amazon Time Sync service
    - 169.254.169.123
  - DHCP traffic
  - Mirrored traffic
  - To VPC router reserved address
    - eg 10.0.0.1
  - Between VPC endpoint ENI and Network Load Balancer ENI
### VPC Traffic Mirroring
- Non intrusive way to capture and inspect traffic
- Configuration
  - Define Source ENIs
  - Define Target ENIs or NLB
  - Optional filter
- Dependency
  - Same VPC or if VPC peering enabled
- Architectures
  - Mirror all traffic to an NLB with autoscaling EC2 security appliances
  - Mirror traffic into cloud traffic broker
    - Send traffic to specific security appliance types
  - Automated response
    - GuardDuty -> Eventbridge -> Lambda
      - Enable mirroring with log storage
  - Centralised VPC monitoring using Transit Gateway
### VPC Network Access Analyzer
- Define rules and continuously evaluate them
  - Network Access Scope
    - json document
  - Example
    - Source: AWS::EC2::InternetGateway
    - Destination: AWS::EC2::NetworkInterface
    - DestinationPorts: 1433, 3306, 5432
### VPC Peering
- Privately connect 2 VPCs
  - Must NOT overlap CIDRs
  - Must update route tables with CIDR in both directions
  - Functions as if on same network
  - Can work across AWS accounts or regions
  - Is NOT transitive
### Transit Gateway
- Acts as a hub and spoke connection between 1000s of VPC and on prem
- Can share across region
- Can share accross account using RAM
- Supports IP Multicast
- IF requirement to increase bandwidth of Site-to-Site VPN
  - Equal Cost Multi Path routing (ECMP)
## VPN
### 4 Scenarios
- AWS Site to Site VPN
  - IPsec VPN connection
    - More secure than SSL VPN
  - Between VPN and remote network
    - Desirable where users work on-site
    - Offsite users need to be connected to Customer Gateway device first
  - Requires
    - Virtual Private Gateway
      - VPN Concentrator on AWS side
      - Created and attached to the VPC
    - or Transit Gateway
    - Customer Gateway
      - Software or physical appliance on customer side
      - Use the public IP of the appliance
      - Or the Public IP of the NAT Device in front of appliance
      - Must enable Route Propagation for Virtual Private Gateway in the route table in associated subnets
      - If you need Ping then must enable ICMP protocol in security groups
- AWS Client VPN
  - Managed client based VPN
  - Authentication options
    - Active Directory Auth
      - AWS Managed AD or on premises AD
      - Supports MFA
    - Mutual Authentication
      - Certificate based
      - Upload server cert to AWS Certificate Manager
      - Recommend 1 client cert per user
    - Single Sign On
      - Supports IAM Identity Center / AWS SSO
      - SAML 2.0 based
      - Only 1 IDP at a time
  - Users can connect from any location
- AWS VPN CloudHub
  - Hub and spoke VPN
  - Connect two+ on premises networks
  - Requires multiple customer gateways
    - Each with public IP address
    - Each use unique BGP ASN
    - Setup dynamic routing and configure route tables
- Third Party Software VPN
  - Launch an EC2 instance with VPN appliance
  - Gives flexibility to manage
## Direct Connect
### Features
- Dedicated network connection between on-premises and AWS
  - Private connection
  - Lower latency
  - Higher bandwidth
- Types
  - Dedicated connections
    - 1Gbps, 10Gbps, 100Gbps
    - Request to AWS then completed by partner
  - Hosted connections
    - 50Mbps, 500Mbps to 10Gbps
    - Requests made via partners
    - Capacity added or removed on demand
  - Lead times >1 month
- Encryption options
  - Not encrypted by default
  - Create an IPsec tunnel on top
    - Max 1.25Gbps per tunnel
    - Layer 3
  - Or setup MacSec encryption
    - Only works on 10Gbps and 100Gbps connections
    - Layer 2
### Implementation patterns
- To access resource inside a VPC
  - Create a private VIF to a VGW attached to the VPC
  - Up to 50 VIFs per DC (50 VPCs)
  - Restricted to the AWS region of the DC
- To access VPCs in different regions
  - Create a VIF to a DC associated with multiple VGWs
  - 1 BGP peering per DC GW per DC
  - Does not work for VPC to VPC connectivity
- Most scalable and manageable option
  - Create a transit VIF to a DC GW associated with a Transit Gateway
  - Connect up to 3 Transit GW across different Regions/Accounts
- To access AWS public endpoints from a public IP
  - eg S3/DynamoDB
  - Create a VPC connection to Transit GW over DC public VIF
### Resilience
- 1x DC is a SPOF
- Consider 2+ DC lines with auto failover
- Consider a VPN connection as secondary
  - Multiple VPN combined with ECMR/ECMP is an alternative
## S3
### Preserving data
- Write Once Read Many (WORM)
  - S3 Object Lock
    - Retention Periods
      - Fixed Period of time
    - Legal Holds
      - Immutable with no time limit
      - Used by principal with s3:PutObjectLegalHold
    - Compliance mode
      - Cannot be overwritten by any user including root
    - Governance mode
      - Only users with special perms can change
  - Glacier Vault Locking
    - call initiate-vault-lock command
      - Triggers 24h to validate lock policy before it expires
      - complete-vault-lock
        - uses the lock-id
      - Can be aborted within 24h
    - Vault policies
      - Vault Access Policy
        - restricts user access permissions
      - Vault Lock Policy
        - immutable
        - examples
          - cannot delete for x period of time
          - cannot change unless have tag
      - Uses a JSON format policy
- S3 replication rules
  - Same region replication
  - Cross region replication
  - Replicate existing objects
    - Requires a one time batch operation
  - Optional enable delete markers replication
    - Still does not replicate deletes
  - There is no replication chaining
  - S3 replication permissions
    - IAM role in the replication config
      - Allow
        - kms:Decrypt
          - Condition: StringLike: kms:ViaService {{s3 source region}}
          - Condition: StringLike: kmsEncryptionContext:aws:s3:arn {{s3 source bucket/keyprefix1*}}
          - Resource: {{KMS key ARNS used to encrypt} source}
        - kms:Encrypt
          - Condition: StringLike: kms:ViaService {{s3 destination region}}
          - Condition: StringLike: kmsEncryptionContext:aws:s3:arn {{s3 destination bucket/keyprefix1*}}
          - Resource: {{KMS key ARNS used to encrypt destination}}
        - s3:GetObjectVersionForReplication
- Optional enforce MFA to delete
### Archiving data
- Types
  - Standard
  - Infrequent Access (IA)
    - Min 30 days in current storage
  - One Zone Infrequent Access
    - Long lived, rapid but less frequent
    - One AZ
  - Intelligent Tiering
    - Longlived data with unpredictable patterns
  - Express One Zone
    - High performance frequent access
  - Glacier
    - Instant Retrieval
    - Flexible Retrieval
    - Retrieval options
      - Expedited
        - Provisioned capacity
          - Guarantee 3+ expedited every 5mins
      - Standard
      - Bulk
  - Glacier Deep Archive
- Lifecycle rules
  - Move, expire or delete data on conditions
### Assessing encryption status
- S3 Batch
  - Perform bulk operations on existing objects
    - eg encrypt
- S3 Inventory
  - Get list of all objects and associated metadata
- S3 Select or Athena
  - Identify and filter on only unencrypted objects
### Ensure bucket owner has control
- StringEquals s3:x-amz-acl: bucket-owner-full-control
### S3 Block Public Access
- Option to set at account level
- Option to set at bucket level
- Sub options for
  - Any | New access control lists
  - Any | New bucket or access point policies
### S3 Encryption at rest
- Server Side Encryption
  - SSE-S3
    - AWS manages the encryption keys
      - Default enabled
      - Glacier uses AES256 keys under AWS control
    - Enforce with bucket policy
      - (Deny) Condition StringNotEquals s3:x-amz-server-side-encryption: AES256
  - SSE-KMS
    - Customer Managed Key
      - AWS Managed
      - Or, Customer Managed
        - Must be created beforehand
    - Protects against physical theft from AWS datacentres
    - Enforce with bucket policy
      - (Deny) Condition StringNotEquals s3:x-amz-server-side-encryption: aws-kms
    - Reduce cost of S3-KMS
      - Use an S3 Bucket Key
  - SSE-C
    - Customer provided encryption keys
      - Customer manages the keys
      - AWS uses the key provided in the request
        - Removed from memory after encryption
      - AWS generates a salted HMAC of the key
      - Enforce with bucket policy
        - (Deny) Condition: Null: s3:x-amz-server-side-encryption-customer-algorithm: true
  - Upload file greater than 4KB
    - Uses envelope encryption
    - Requires IAM perms
      - kms:Decrypt
      - kms:GenerateDataKey*
- Client Side Encryption
  - eg Amazon S3 Client-side encryption library
### S3 Encryption in transit
- Enforce HTTPS to bucket
  - Deny -> Condition: Bool: aws:SecureTransport: false
    - Apply to bucket policy
### Redact S3 data on the fly
- Use S3 Object Lambda
  - Requires Lambda function
    - Needs IAM perms for WriteGetObjectResponse
  - Requires S3 Access Point
### S3 Event Notifications
- Examples
  - S3:ObjectCreated
  - S3:ObjectRemoved
  - S3:ObjectRestore
  - S3:Replication
- IAM Permissions required
  - Allows the S3 bucket to send in messages
    - Principal -> Service -> S3
    - Condition -> ArnLike -> S3 bucket
  - SNS Resource Access Policy
  - SQS Resource Access Policy
  - Lambda Resource Policy
- Can filter on object names
- Integration options
  - SNS
  - SQS
  - Lambda
  - EventBridge
    - All events if turned on
    - Can use rules to connect to 18+ AWS service destinations
### S3 Authorization
- User Context
  - If IAM principal granted by parent AWS account
- Resource Context
  - Not public by default
  - Resource based policies
- Object Context
  - If bucket owner = object owner then access granted using Bucket Policy
  - If bucket owner != object owner then access granted using object owner ACL
  - default enabled Bucket Owner Enforced Setting for Object Ownership
- Bucket Operations
  - Action: s3:ListBucket
  - Resource: arn:aws:s3:::foo
- Object Operations
  - Action: s3:GetObject, PutObject
  - Resource: arn:aws:s3:::foo/*
- ACL related Operations
  - Ensure grant ownership to Account
    - (Better) Canned ACL
      - Deny Condition: StringNotEquals: s3:x-amz-acl: bucket-owner-full-control
    - Define specific ownership
      - Deny Condition: StringNotEquals: s3:x-amz-grant-full-control: id=AccountA-CanonicalUserId
- Troubleshooting
  - Insufficient delivery policy to S3
    - check Principal: Service allows relevant AWS services
    - check Allow action GetBucketAcl and ListBucket
    - recommend Condition: StringEquals: AWS:SourceAccount: {{accountID}}
    - check Allow PutOject on S3 Bucket path/*
### S3 Access Points
- Scale permissions to buckets and objects
- Has a DNS name
- Origin options
  - VPC origin
    - Requires a VPC Endpoint
      - VPC Endpoint also has a policy
        - Must grant access to object and access point
  - Internet origin
- Simplify the bucket policies
- Apply an access point policy
  - Similar content to bucket policy
### S3 Multi Region Access Points
- Provide a global endpoint spanning regions
- Dynamically route requests to lowest latency
- Failover controls
  - Define as active or passive
- Create replication rules
  - 1 or 2 way bucket replication to sync data
    - Requires versioning enabled
### S3 CORS
- Origin
  - Scheme
    - http
  - Protocol
    - www.example.com
  - Port
    - 80
- CORS headers
  - Access-Control-Allow-Origin
- Preflight
  - Request
    - OPTIONS /
## Host: www.other.com
## Origin: https://www.example.com
  - Response
    - Access-Control-Allow-Origin: https://www.example.com
    - Access-Control-Allow-Methods: GET, PUT, DELETE
## EBS
### Encryption options
- Always encrypt new volumes
  - Setting per region per account
  - Not set by default
### Backup
- Data Lifecycle Manager
  - Can consider superseded by AWS Backup
  - automate creation, retention and deletion of EBS snapshots
### Wiping
- AWS will overwrite EBS volumes before releasing to another customer
## EFS
### Encryption options
- If unencrypted -> No option to just encrypt
  - Create new encrypted EFS filesystem
  - Migrate files using AWS DataSync
## Lambda
### Default global deployment
- Can access public internet
- Can access global AWS services eg S3/DynamoDB
### Deployment to a private VPC
- Define the VPC ID, subnets and security groups
- AWSLambdaVPCAccessExecutionRole
  - AWSLambdaENIManagementAccess
    - ec2:{{Create|Describe|Delete}}NetworkInterface
- Other resources must allow Lambda security group
- To get internet access inside VPC requires going through NAT GW + Internet GW
### Secrets options
- Sharing secrets with lambda using parameter store
  - Grant execution role access to KMS key
  - Create an encrypted parameter as SecureString
  - Lambda code config parser function to reuse across invocations
- Lambda environment variables
  - Not the most secure
  - Best performing
  - Difficult to audit
  - Can leak secrets via readonly policy as part of getFunctionConfiguration
- Secrets Manager
  - Advantage of rotating secrets and replication across regions
- UseLambda extensions with a cached secret layer
## CloudShell
### Browser based shell in AWS Console
### Preinstalled common libraries and tools
### Can define a VPC environment
### awsconfigure export-credentials --format env
- Prints short lived tokens
## AWS Acceptable Use Policy (AUP)
### Governs use of AWS services
## AWS Signer
### Fully managed code signing service
### Uses a Signing Profile
### Integration with Lambda
- Requires packaging in a ZIP
### Revocation mechanisms
- RevokeSignature Api
- RevokeSigningProfile Api
- Irreversible - use in critical scenarios
## Personal Health Dashboard (PHD)
### Personalisedview of service events that may impact your AWS resources
- Open Issues
  - Operational Issues
    - Increased latency
    - Power loss
- Scheduled changes
  - Upcoming maintenance
- Notifications
  - Billing notifications
  - Certificate rotations
  - End of life support
## Cost Explorer
### Visualise understand and manage AWS costs over time
### Create custom reports
### Choose optional savings plans
### Forecast usage up to 12 months in advance
### AWS Cost Anomaly Detection
- Continuous monitor costs and use ML to detect unusual patterns
- Individual alerts or daily/weekly SNS
## Trusted Advisor
### Analyses your AWS environment and gives best practise recommendations
- Issues that are your responsibility to resolve
### Basic/Developer plan can access subset of APIs
- Service Limits = all checks
- Security = 6 checks
### Publishes service limit metric to CloudWatch
### Trusted Advisor Exposed Access Keys CloudWatch Event
## AWS Abuse Report
### Contact AWS Trust and Safety Teams
- If contacted
  - Respond to email
  - If not AWS may suspend account
### Examples
- SPAM
- DDoS
## AWS Backup
### Managed service without needing scripts
### Backup policies known as Backup Plans
- Define
  - if tag based
  - frequency
  - backup window
  - if/when to transition to cold storage
  - retention period
  - vault lock policy => worm
    - even root cannot delete
### on-demand and scheduled backups
### tag based backup policies
## VPC Lattice
### Solves problems
- Can never have overlapping IP ranges or CIDR blocks
- Zero trust authZ with IAM
- Doesnt use IP Addresses or ENIs
- No proxy service mesh or sidecars
- Integrates instances containers and lambdas
- Central logging and auditing of traffic
### Service Network
- logical grouping to simplify connectivity
- associated to 1 or more VPC to enable Clients to send requests
  - Defense in depth options
    - Reference vpc lattice managed prefix lists
- associated to 1 or more services in your own or other accounts
- has a Service Network IAM policy for security of service to service communication
- Works only within 1 region
- External ingress into Service Network
  - Recommendation
    - NLB in public subnet with IGW
    - Proxy fleet running serverless tasks on Fargate
      - Open source NGINX
- Cross Region ingress into Service Network
  - Options
    - VPC peering
    - Transit Gateway
    - Cloud WAN
### Service
- represents customer owned application that extends across compute
- listeners
  - protocol
    - HTTP
    - HTTPS
    - TLS
      - application does decryption
      - auth policies are limited to anonymous
      - lambda targets NOT supported
      - must have custom domain
  - port number
- routing rules
  - control application flows
    - path
    - method
    - header based
    - weighted routing
  - default rules
    - can NOT have conditions
  - rule priority
    - from lowest value to highest
  - rule actions
    - forward
      - toone or more target groups
      - if multiple then must specify weight for each target
    - fixed-response
      - eg return a 404
  - rule conditions
    - must be exact match no wildcards
    - Header match
      - standard or custom HTTP header fields
    - Method match
      - standard or custom method
    - Path match
      - path pattern in request URL
- N number of target groups
  - HTTP targets
  - Lambda function targets
    - Requires aws lambda
## add-permission
## --principal vpc.lattice.amazonaws.com
## --action lambda:InvokeFunction
    - Use function alias
  - EKS deployments can use Gateway Controller to auto register the Service Network, Service and IP based targets
  - ALB targets
    - ALB must be in same account as target group
    - Can use HTTPS listeners only if lattice service uses same TLS cert
    - ECS deployments use ALB
- has a Service IAM Policy
- can be shared via AWS RAM
### Service Directory
- list of all VPC lattice services
  - within an account + any shared via RAM
### Auth Policies
- IAM resource policy documents
  - attached to service networks
  - or attached to services
  - Policy
    - Principal
      - eg IAM role or assumed-role
    - Action
      - vpc-lattice:Invoke
    - Resource
      - arn:aws:vpc-lattice:us-west-2:ACCOUNT:service/foo
    - Condition
      - StringEquals: vpc-lattice-svcs:SourceVpc: foo
- Use cases
  - Configure course grained policy to only allow authN from principals in AWS Organization
    - eg Condition StringEquals aws:PrincipalOrgID: foo
  - Delegate to service owners fine grained control over service specific policies
    - eg restrict access to principals with specific project tag
### Request signing
- If using IAM AuthZ then requests must be signed
- Lattice does not support PAYLOAD signing
  - must use header x-amz-content-hash: UNSIGNED-PAYLOAD
### Monitoring
- All service network traffic can be logged in single CloudWatch log group
### Service Discovery
- DNS based discovery model
- Unique global DNS name
  - Managed by VPC Lattice in Route53 public hosted zones
  - Option to use custom domain name as CNAME or ALIAS in route53
  - Recommendation to create Route53 HostedZones in each service account
    - Add nameserver delegation from rootDNS to development teams
- Manages SSL/TLS for HTTPS
  - Or custom certs using ACM
### Cost
- Comparable to Transit Gateway
- Significantly more than PrivateLink
- VPC Peering instead has no cost