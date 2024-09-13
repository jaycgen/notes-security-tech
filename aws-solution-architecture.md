# AWS Solution Architecture
## Control Tower
### Landing zone
- One landing zone per organisation
### Account Factory
- Automate provisioning of new accounts
- Shared Accounts
  - Management account
  - Log archive account
  - Audit account
## Organizations
### Hierarchy of accounts
- Under the Management Account
### Consolidated billing
- Volume discounts
- Combined view of charges
### SCPs
- Filter policies that only allow the specified services and actions
## Resource Access Manager
### Share AWS resources across accounts
- Examples
  - Aurora DB clusters
  - Codebuild projects
  - EC2 transit gateways
  - AMIs
  - Route53 forwarding rules
- CIDR Use Case
  - Provision a VPC customer managed prefix list
  - Add CIDR blocks
  - Share using RAM
### Sharing
- Create a Resource Share
- Specify resources
- Specify accounts
## Route53
### DNS Management
- EIPs
- EC2s
- S3
- ELBs
- Cloudfront distributions
### Hosted zones
- Container for DNS records
  - Public hosted zone
    - Auto creates a name server NS record
    - Auto creates a Start of Authority SOA record
  - Private hosted zone
    - Only resolvable inside VPC
    - Must create a Resolver inbound and/or outbound endpoint
      - Inbound endpoint
        - Lets DNS resolvers on your network forward DNS to Route53
      - Outbound endpoint
        - Lets Route53 conditionally forward queries to resolvers on your network
- Record types
  - A record
  - AAAA record
    - ipv6
  - CNAME record
    - Cannot create a CNAME for an apex record
- Alias
  - Enables mapping to AWS resource instead of IP
### Domain Registration
- Supports multiple TLDs
- Specify how many years
- Some allow auto renew
### Traffic management
- Routing
  - Simple routing
    - Map to a resource
  - Failover routing
    - Active passive routing failover
  - Latency Routing
    - Route53 serve requests in lowest latency
    - Requires creating latency records in regions
  - Geoproximity Routing
    - Uses Route53 traffic flow
      - Requires creating traffic flow policies
      - Define where resources are located
    - Route traffic based on geographic location of resources (and users)
  - Geolocation Routing
    - Route based on location of users
      - Helps to localise content
    - Works by mapping IP addresses to locations
  - Weighted routing
    - eg canary/feature testing
- DNSSEC
  - Prevents hijacking traffic via spoofing
  - Pre-requisites
    - TLD must support DNSSEC
    - DNS service provider must support it
    - Must configure DNSSEC before adding public keys for the domain
      - Have route53 create a key signing key (KSK) via KMS
      - Create a chain of trust for hosted zone
        - Add a Delegation Signer (DS) record to the parent zone
    - Add public encryption keys to route53
      - Configure under Registered Domains
      - Choose manage keys
      - Specify algorithm
### Availability monitoring
- Route53 health check
  - health of a resource eg web server
    - If using Alias then just set Evaluate Target Health
  - status of other health checks
  - status of CloudWatch alarm
  - Choose 10 or 30 seconds
- Active-active setup
  - All considered as active unless fail due to a health check
- Active-passive setup
  - Create secondary or more records
## Storing Secrets
### Secrets Manager
- Encrypts secrets at rest
  - Works with KMS
- Rotates secrets
  - Uses Lambda rotate functions
    - If inside a VPC
      - Need to add a NAT gateway
      - Or need to configure Secrets Manager service endpoint in the VPC
- Stores metadata
- Versioned
- Enables copying across regions
- Enables role access across accounts
- Priced per secrets and API calls per month
### Systems Manager Parameter Store
- Key value pair store
- Secure String
  - Encrypted parameters use KMS
- Free for <10000 parameters
## IAM
### IAM Policies
- Amazon Resource Names (ARN)
  - arn:partition:service:region:account-id:resource-id/resource-id
  - partition
    - generally = AWS
  - service
    - eg s3, iam, rds
- Best Practise
  - full-access
  - billing
  - logs
  - developers
  - read-only
  - use-existing-iam-roles
  - iam-admin
  - If Using Users
    - allow-access-to-other-accounts
    - allow-access-to-all-other-accounts
  - If Using SSO
  - allow-access-from-other-accounts
  - auto-deploy-permissions
  - allow-auto-deploy-from-other-account
- Identity based
  - Inline
    - Embedded into a user, group or role
  - Managed policies
    - standalone
- Resource based
  - Attached to resources like S3 buckets or KMS keys
  - inline only
  - Trust policies
    - Attached to a role and define principals
### IAM Roles
- Best Practise
### Users
- Users
  - Root user
    - Logs in with email address
  - Max 5000 users per account
- Groups
  - Cannot nest
  - User can have max 10 groups
- Federated Users
## EC2
### AMI Factory
- Requires
  - Packer
  - Base O/S distribution
  - Partition scripts
- Build Process
  - Create Packer template
  - Launch ami-builder ec2 instance
  - Copy Packer template onto EC2 using SCP
  - SSH into EC2 and run packer build
  - Terminate ami-builder
- Harden
### Image Builder
- Pipeline recipe for creating template
### Placement group
- cluster
  - placed closed together
    - low latency
- partition
  - placed across different partitions
    - do not share same underlying hardware
    - max 7 partitions per AZ
- spread
  - strictly placed across distinct hardware racks
  - limited to 7 instances in a group per AZ
- troubleshooting insufficient capacity
  - Stop and restart the instances
### Elastic Fabric Adapter
- Higher network throughput
- Cannot use on a Windows instance
  - Windows instances must use Elastic Network Adapter instead
### Types
- General Purpose
- Compute Optimised
  - High performance processors
- Memory Optimised
  - Large datasets in memory
- Accelerated Computing
  - Hardware accelerators
- Storage optimised
  - EC2 Instance Store
    - Physically mounted disks
- Nitro based
  - Bare metal
    - Up to 64000 IOPS
### Pricing
- On Demand
- Spot
  - For workloads that can tolerate disruption
  - Variable pricing - up to 90% discount
- Standard Reserved Instances
  - Long term commitment
    - Reserved Instance Marketplace
      - Resell unused capacity
- Scheduled Reserved Instances
  - Long term commitment to a specific frequency & duration
  - Daily, Weekly or Monthly
- Dedicated Hosts
  - Pay for the host
  - Launch as many instances as want
  - Useful for licenses that are reliant on sockets and cores
- Dedicated Instances
  - Pay per instance
  - Guarantee other customer data not on same hardware
### EC2 Instance Store Volumes
- Ephemeral block storage attached to instance
- Price included as part of instance usage
### Status checks
- instance health check
  - built in
- ELB health check
  - need to provide port and protocol
- Auto scaling and custom
### Auto Scaling
- Min, Max, Desired
- Spans AZs but does not span multiple regions
- Instance warm up
- Cool down
  - Interval between two scaling actions
- Types
  - Simple scaling
    - % CPU utilisation
  - Target tracking
    - Recommended EC2 Scaling - it uses a specific metric
    - Average CPU
    - Average Network In/Out
    - ALB Request Count
  - Step Scaling
    - You choose scaling metrics and threshold values using step adjustments
- Lifecycle hooks
  - Scripts that run and call actions before pending/terminating
    - Pending:Wait
    - Terminating:Wait
  - Can use CloudWatch events to trigger rules
  - Can use SNS notifications
    - Requires SNS topic
    - Requires IAM role
      - Trusted entity EC2 Auto Scaling
      - AutoScalingServiceRolePolicy
### EC2 Networking
- Each EC2 has at least 1 Elastic Network Interface (ENI)
  - Each needs its own Security Groups
- Secondary ENI are useful for licensing
### EC2 Hibernation
- Pay only for the EBS volumes and EIP
- Has to be configured at launch time
### EC2 User Data
- Used to bootstrap
- Run by the root user
- Not validated or checked
- Limited to 16KB
- Not secure - can be accessed by anything on the instance
## ECS
### Highly scalable container orchestration service
### Eliminates need to install and operate container orchestration
### Options
- Can run on serverless compute = Fargate
- Can run on EC2 instances that you access and manage
- Clusters can be a mix of both types
### Requires a cluster
- Container Agent = Instance Role
  - ecsInstanceRole IAM policy
- ECS Security
  - Recommend to block containers from accessing the EC2 metadata
    - ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST
      - False
  - Recommend to block tasks running in bridge mode
  - Use awsvpc network mode
- Create task definitions
  - Which docker image
  - What resources to allocate
  - What volumes to mount
  - What network mode
    - Default
      - Linux
        - Bridge
      - Windows
        - NAT
    - Bridge
      - All containers on the same bridge can connect
    - Host
      - Bypass virtual network
      - Uses host ports which must be unique
    - awsvpc
    - None
  - What placement strategy
    - Binpack
      - Close together - minimise CPU/mem use
    - Random
    - Spread
      - Availability zones
  - Task Execution IAM role
    - Trust policy
      - Principal Service ecs-tasks.amazonaws.com
      - AssumeRole with conditions
        - ArnLike SourceArn
        - StringEquals SourceAccount
    - Permissions
      - Pull docker images
      - Publish container logs
      - Use Secrets Manger credentials to access ECR
      - Pass sensitive data with Parameter Store or Secrets Manager
- Run ECS Tasks
  - Task IAM Role
    - Permissions
      - Make API calls
    - Trust policy
      - Principal Service ecs-tasks.amazonaws.com
      - AssumeRole with conditions
        - ArnLike SourceArn
        - StringEquals SourceAccount
### Storage
- On EFS or FSX
### Container Security
- Use minimal or distroless images
- Create set of curated images
- Scan images for vulnerabilities
- Scan application packages for vulnerabilities
- Scan application source code
- Run containers as non root
- Use read only root file system
- Use immutable tags in ECR
- Avoid running containers as privileged
- Remove unnecessary Linux capabilities
### Integration
- SQS
- Kinesis Data Stream
### Elastic Container Registry (ECR)
- Ensures access is only possible over HTTPS
## Cost Explorer
### Features
- Analyse historical spending
- Predict future costs
- Identify cost saving opportunities
- API with pagination for automation
## EKS
### Deployment choice
- Fargate vs EC2
### Authentication
- IAM Authenticator for Kubernetes
  - configured using aws-auth ConfigMap
### Control Plane
### Worker Nodes
- Must have DNS support for cluster VPC
- Must configure user data
- aws-auth configmap must have NodeInstanceRole of worker nodes
## ELB
### Types
- Application Load Balancer (ALB)
  - HTTP/HTTPS
    - Listener rule options
      - one of each
        - path-pattern
          - in the request URL
        - http-request-method
        - source-ip
        - host-header
      - one or more
        - http-header
        - query-string
          - key value pairs
  - Cannot be associated with an Elastic IP
- Network Load Balancer (NLB)
  - TCP/UDP/TLS
  - Can be associated with an Elastic IP
  - Supports an HTTP health check
- Gateway Load Balancer (GWLB)
  - 3rd party virtual appliances
  - Layer 3
- Classic Load Balancer (CLB)
### How works
- Evaluate listener rules in order
- Route using algorithm
  - round robin
  - least outstanding requests
  - flow hash algorithm
    - sticky based on
      - protocol
      - source
      - destination
      - TCP sequence number
- Idle timeout
  - Connection keepalive time
    - Default 60s
    - Max 4000 seconds
- Health check frequency
  - Customisable between 5-300 seconds
## Lambda
### Serverless computing
- Pay only for compute time
### Multiple runtimes
- Java
- Go
- Ruby
- Node.js
- Python
### Concurrency limit
- Number of requests a function will serve at a given time
  - Default 1000 per region
- Reserved
  - Pool of requests can only be used by function that reserved
- Provisioned
  - Initialise a number of execution environments ready to respond
- SnapStart
  - Mitigate cold starts
  - Firecracker microVM takes snapshot of memory of initialized execution environment
### Sizing
- Memory
  - 128mb to 10240 MB
- CPU
  - 1769 MB mem = 1 vCPU
- Timeout
  - Default 3s
  - Max 900s
### Lambda@Edge
- Cloudfront feature that runs Lamda in edge locations
- Triggers
  - Viewer request
  - Origin Request
  - Origin response
  - Viewer response
- Common use cases
  - Send different objects based on user agent header
  - Inspect headers or authorization tokens
  - Modify headers and re-write URL paths
  - Redirect unauthenticated users
### Networking
- Lambda not able to access VPC resources by default
  - Connect function to VPC
    - Creates an elastic network interface for each included subnet
      - 2+ subnets recommended for HA
    - Function execution role must have AWSLambdaVPCAccessExecutionRole
    - Implies that function has no internet access unless VPC has Internet Gateway and/or NAT
- Lambda Function URL is a unique URL endpoint
## KMS
### Customer Master Key (CMK)
- Can be AWS Managed or Customer Managed
- Keys are isolated to specific region
- FIPS 140-2 (L2) compliant by default
- CMKs can encrypt max 4KB of data
### Common Scenarios
- Rotate a KMS key with imported material
  - Create new key and repoint alias
- Manage many keys without editing policies
  - Use grants in AWS KMS
- Prevent tampering of ciphertext using additional authenticated data
  - Add kms:EncryptionContext condition
### Data Encryption Keys (DEK)
- Generated using a CMK
  - Provides the plaintext DEK + Ciphertext DEK + destroys and does not store the DEK
- Can encrypt data larger than 4KB
## WAF
### Common Scenarios
- Block common web exploits
- Block high volume requests from specific user agent HTTP headers
### Common Integrations
- Cloudfront
- ALB
- API Gateways
- Cognito User Pool
- AppRunner Service
- Verified Access Instance
### Common Management
- Use Firewall Manager
  - Across accounts and resources
  - WAF
  - Shield
  - Network Firewall
### WebACLs
- Rule Groups
- Rules
  - Managed rules
    - Use default version or static version
  - Custom rules
    - Regular rules
    - Rate based rules
- Functionality
  - Allow
  - Block
  - Count
  - Captcha/challenge
  - Text transformation before inspecting
- Logging
  - Cloudwatch
  - S3
  - Firehose
  - must have aws-waf-logs prefix
- Capacity
  - Measured in WCUs
    - Max 5000 for a group/acl
    - Charged if > 1500
## Network Firewall
### Common Scenarios
- Govern ingress
- Govern egress
- Network Firewall can inspect traffic equivalent to an IDS/IPS using Suricata
### Components
- Firewall
- Firewall Policy
  - One per firewall
- Rule Group
  - Stateful options
    - Suricata compatible rule strings
    - Domain list
      - e.g. list like .amazonaws.com
    - Standard stateful rules
      - egcsv with source and destinations
  - Stateless options
### How to
- Deploy in multiple AZs
  - One subnet per zone
    - Each must have at least 1 available IP
- Update VPC route tables to send incoming/outgoing traffic via firewall
- Tag based
  - Map workloads into Resource Groups
  - Use Network Firewall Rule Groups
## CloudFront
### Create Cloudfront distribution
- Origin Settings
  - Add a custom header
  - Associate the Origin Access Control
  - Enable Origin Shield
- Cache Behaviour
  - Specify the origin
    - Specify multiple origin for failover
  - Specify the path pattern
  - Response Headers Policy
    - Enforce secure headers back to client
  - Viewer Protocol Policy
    - Require HTTPS from client
    - Or, redirect HTTP to HTTPs
  - Define allowed HTTP Methods
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
### Create Origin Access Control
- Specify S3 origin
- Supports SSE-KMS
- Require always signing
- Enforces HTTPS to S3 origin by default
## VPC
### Security Groups
- Instance level
- Only allow rules
- Stateful
- Prefix Lists
  - Help represent AWS services instead of via IP range
    - Add DestintationPredixListId
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
- Allow or deny
- Evaluated in order lowest number first
- Default
  - allows all inbound and outbound
- Custom
  - denies all inbound and outbound until add rules
- Remember rules for ephemeral ports 1024-65535
### Internet Gateway (IGW)
- Regionally resilient
  - Covers all AZs in the VPC
- A VPC has 0 or 1 IGW
### NAT Gateway
- AZ Resilient service
- Scales to 45GBps
- Needs to run from public subnet
  - Associated with an Elastic IP
- Enables private IPs to masquerade behind public IP
  - Does not work with IPv6
### Reachability Analyzer
- Feature to perform network diagnostics between 2 resources
- Source/destination
  - EC2 instance
  - Network Interface
  - Subnet VPC peering connection
  - VPN connection
  - Transit gateway connection
## Direct Connect
### Features
- Dedicated network connection between on-premises and AWS
- Private connection
- Lower latency
- Higher bandwidth
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
## Global Accelerator
### Features
- AWS provides set of static IPs
  - Single fixed entry point for clients around the world
  - Associate with regional endpoints eg ELBs, EIPs etc
## Verified Access
### Trust providers
- Identity based
  - Identity Center
  - OIDC IDP
- Device based
  - Crowdstrike
  - Jamf
  - Jump cloud
### Common Scenarios
- Avoid needing a VPN
- Centralise authentication for corporate applications
## Tasks and Workflows
### Step Functions
- Fully Managed Service
  - Application centric view
- Visual Workflows
- Declarative JSON
- Define state machines
  - Describe steps, relationships, input, output
### Simple Workflow (SWF)
- Tasks
  - Processed by workers
  - Logical steps in applications
  - Write a decider program
    - Separates activities and decisions
    - Language of choice or FLOW framework
### Simple Queue Service (SQS)
- Features
  - Polling method
  - Highly scalable
  - Visibility timeout prevents other consumers from processing
  - Retention period
    - Default 4 days
    - Maximum 14 days
- Queue Types
  - Standard
    - Near unlimited capacity
      - SendMessage
      - ReceiveMessage
      - DeleteMessage
    - Common Scenarios
      - Decouple live user requests from background work
      - Allocate tasks to worker nodes
      - Batch messages for future processing
    - Potential duplication
      - Applications should be idempotent
  - FIFO
    - Preserves the order of messages
    - Messages delivered exactly once
    - Supports up to 300 API calls per second per API
    - Batching increase support to 3000 transactions per second
    - Common Scenarios
      - Ensure user entered commands run in right order
      - Display correct price by sending modifications in order
      - Prevent enrolling user before registering
  - Dead Letter Queues (DLQ)
    - Features
      - Help debugging
      - Can configure alarms for messages
      - Can examine logs for exceptions
  - Delay queues
    - Postpone a message for 0 sec to 15min
- Polling types
  - Long Polling
    - When wait time 20sec > X > 0
    - Searches all SQS servers for messages
    - SQS sends response after collecting at least 1 message
  - Short Polling
    - When wait time is 0
    - Searches only subset of SQS servers to find messages
    - SQS sends response right away
- Important that consumer deletes message
### Simple Notification Service (SNS)
- Features
  - Fully managed messaging and notification service
  - Publish Subscribe Patterns
- Resources
  - Topic
    - Use an SNS topic to send a notification
      - Email
      - Slack
      - Lambda options
        - SNS can create subscription with Lambda as endpoint
        - Lambda can add trigger with SNS topic
    - 1 or more SQS queues can subscribe to a topic
    - Types
      - Standard
        - Nearly unlimited capacity
        - Best effort ordering
        - Up to 100000 topics each with up to 12.5M subscriptions
      - FIFO
        - Up to 300 messages per second
        - 10MB per second per topic
        - Guarantees ordering
        - Only sent to SQS FIFO subscriptions
        - Up to 1000 FIFO topics each with up to 100 subscriptions
        - Deduplicates within 5min interval
    - Consider adding a deduplication ID to the messages
- Message Filtering
  - Subscriber only receive a subset of messages
  - Uses filter policy
    - JSON object
    - Attributes in name: value format
    - Must have all attributes
## Inspector
### Incident Management
### Uses service linked roles
### Engine that analyses system and resource configuration
### Built in library of rules and reports
### Assessment Types
- Network
  - Reachability
    - Processes reachable on EC2 instance port
    - Requires Inspector Agent
- Host
  - Common vulnerabilities
  - CIS Benchmarks
  - Requires Agent
    - Outputs in JSON
    - Delivers over TLS
    - Encrypted with per assessment KMS derived key
    - Stores in S3 bucket
    - Can use SSM Agent
  - Agentless (In Preview)
    - Uses snapshot of EBS volume
- Container Images
  - Scans ECR
- Lambda functions
  - Scans code
  - Uses GenAI to offer fixes
- CI/CD
  - Plugins for Jenkins and TeamCity
  - inspector-scan API can be run via AWS CLI
  - Creates CycloneDX SBOM of container and then scans it
## Config
### Common Scenarios
- Detect disabled VPC flow logs
- Check instance using approved-amis-by-id
- Detect security groups that allow 0.0.0.0/0 inbound
- Detect disabled CloudTrail
- Track usage of API keys on root users
### Common Triggers
- Cloudwatch event
## Detective
### Collects Log data and uses machine learning to build a linked set of data
### Faster more efficient security investigations
### Multi account service that is per region
## Systems Manager
### Explorer
- Customisable operations dashboard
- Aggregated view of operations data across AWS accounts and Regions
### Patch Manager
- Automate process of patching EC2 instances
- Predefined and custom patch baselines
- Set scheduled maintenance windows
### State Manager
- Control configuration details of resources
- Associate with integrations
  - Ansible playbooks
  - Chef recipes
  - PowerShell modules
  - SSM documents
## GuardDuty
### Regional service
### Threat detection service
- Reconnaissance
- Instance compromise
- Account compromise
### Data sources
- VPC Flow Logs
  - Do not have to turn on - Guardduty uses own stream source
- DNS Logs
  - Does not work on 3rd party DNS
- Cloudtrail management events
### Findings
- Severity
  - Low
  - Medium
  - High
- Finding Types
  - Backdoor
  - Behaviour
  - Cryptocurrency
  - Pentest
  - Persistence
  - Policy
  - PrivEsc
  - Recon
  - Stealth
  - Trojan
  - UnauthorisedAccess
- Resource affected
- Action
- Actor
### Trusted IP lists
- Allowed IP addresses which will not generate findings
  - 1 list per account per region
### Threat lists
- Known malicious IP addresses
## Artifact
### Central service of AWS security and compliance reports
### Reports
- ISO
- SOC
- PCI
### Artifact Agreements
- NDAs
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
### Private CA
- Auto renews
- Sends cloudwatch notification
  - Clients can use this to renew
  - AWS_ACM_RENEWAL_STATE_CHANGE
    - Renewed
    - Expired
    - Due to expire
- CA Hierarchies
- Billed per CA per month
### Import certs
- Manual renewal
### Integrations
- ELB
- Cloudfront
- Elastic Beanstalk
- API Gateway
- Cloudformation
## Amplify
### Features
- Build extensible full stack web and mobile apps
### Amplify Studio
- Visual developer environment
- Ready to use UI components
- Define data models
- Implement user auth
- Add file storage
- Import Figma prototypes
### Amplify Libraries
- Open source Javascript libraries
- React, React Native, Angular, Ionic, Vue
### Amplify CLI
- Toolchain to configure and maintain app
- Interactive workflow
- Test and deploy to multiple env
- Infra-as-code templates
  - Loaded into Cloudformation
  - Or loaded into AWS SAM
### Amplify Hosting
- Deploys to Cloudfront
- Setup custom domains and alarms
## Device Farm
### App testing service
- Runs Selenium tests on different browsers and versions
### Supports
- Android
- iOS
- Webapps
- Cross Platform Frameworks
## AWS Deployment Services
### Cloudformation
- Provision and manage AWS resources using templates
  - JSON/YAML
  - Only Resources section is mandatory
  - Parameters section allows adding fields that users must enter
  - Mappings section enables creating lookup tables
  - Conditions section allows decision making
    - CreationPolicy attribute
      - Wait on resource configuraiton actions before stack creation proceeeds
      - Use the cfn-signal helper script
  - Graphical option is Cloudformation Designer
  - Creates Stacks
    - Bundle stacks into nested stack
  - StackSets
    - Deploy across multiple accounts in Organization
### Serverless Application Model (SAM)
- Extends cloudformation
### Elastic Beanstalk
- Managed platform to upload application code
  - Web Server env
  - Worker env
- Deploys the necessary resources to run the app
- automatically handles the details of capacity provisioning, load balancing, scaling, and application health monitoring
### CodeDeploy
- Fully managed deployment service
### ECS Anywhere
- Run & manage container workloads on own on-premises infra
### EKS Anywhere
- Run K8s cluster on own hardware, control plane, data plane
### EKS on AWS Outposts
- Uses physical AWS Outpost rack on premises
### OpsWorks
- Configuration Management services
  - Chef Automate
  - Puppet Enterprise
### Proton
- Automate container and serverless
- Use pre-approved stacks
- Offers a self service portal
- Supports GitOps templates
## AWS AI
### SageMaker
- Build, train and deploy ML models
- Fully managed infrastructure, tools, workflows
### Computer Vision
- Reokognition
  - Recognise certain objects
    - Faces
    - Texts
    - Scenes
    - Labels
- Lookout for Vision
  - Identify defects
- Panorama
### Data Extraction and Analysis
- Textract
  - Extract texts
  - Scanned documents, notes, images
  - Output into table form or CSV
  - Ask questions using NLP
- Augmented AI
  - Human review workflows
- Comprehend
  - NLP insights in text
  - Sentiment
  - Key phrases
  - PII
  - Requires raw text
### Language AI
- LEX
  - Develop voice or text based chatbots
- Transcribe
  - Transcribe speech to text
  - Generate transcripts
- Polly
  - Transcribe text to speech
  - Can upload own lexicon
  - Can choose voices
### Customer Experience
- Kendra
  - Intelligent search service
  - NLP based search
  - Search multiple data sources
- Personalize
  - Personalised recommendations
  - Uses past activity and behaviour
- Translate
  - Language translation
  - Customise output
    - Company/domain specific language
    - Set acronyms
    - Set formality
    - Mask profanity
### Business Metrics
- Forecast
  - Import or stream time series data
  - Predict future
    - Sales
    - Capacity
    - Traffic
- Fraud Detector
  - Identify fraud
    - Fake reviews
    - Spam accounts
- Lookout for Metrics
  - Detect anomalies in business metrics
### DevOps
- DevOps Guru
  - Detect abnormal behaviour
  - Identify operational defects
- CodeGuru Reviewer
  - Provide intelligent recommendations for improvements
    - Code quality
    - Efficiency
    - Performance
- CodeGuru Profiler
  - Collects runtime performance data
- CodeWhisperer
  - Generates code and functions
## Managed Grafana
### Collect metrics
### Show Dashboards
### Integrations
- Self hosted data sources
- 3rd parties
## Managed Prometheus
### Collect system metrics
### Use PromQL queries
### Centralise alerts using Alert Manager
## Directory Service
### Managed Microsoft AD
- Built on AD and Windows Server 2012 R2
- Seamless Domain join for new Windows Server EC2
### AD Connector
- Proxy service
  - AWS compatible services to an on premises AD
  - Not compatible with RDS SQL
### Simple AD
- standalone directory powered by Samba 4
### Cloud Directory
- Cloud native directory
- Store 100s of millions of objects
## Fargate
### Serverless compute engine for containers
- Works with ECS
- Works with EKS
- No manual provisioning, patching, cluster capacity or infra management
## Macie
### Machine learning to discover, classify and protect sensitive data
- PII
- PHI
- API keys/secrets
### Data source
- Cloudtrail event logs and errors
- S3 objects
### Alerts
- Basic
  - Managed
  - Custom
## Cognito
### User Pools
- Directory of users
  - Specific to 1 region
- Enable user login via 3rd party IDP
### Identity Pools
- Federate access to AWS Services
  - eg S3, DynamoDB, Lambda etc
- Trades OIDC token for Temporary AWS credentials
## CloudTrail
### Common Scenarios
- Prevent Tampering
  - Enable CloudTrail log file validation
- Some accounts cant send logs
  - Check Central account S3 bucket policy
  - Check all trails are active
- Where to view events
  - CloudTrail console
  - CloudTrail Lake
    - Run SQL queries on event logs
    - Converts JSON to Aparche ORC format
### Types of events
- Management events
- Data events
- Insights events
### One free copy of management event logs per region
- Log file validation enabled by default
  - SHA256 hashing
  - SHA256 with RSA for signing
### Event history
- Visible even without a trail for past 90 days
- Delivers events within 15mins typically
### Filters
- Read only events
- Write only events
### Storage
- CloudTrail sends logs to S3 bucket by default
  - Use Athena to analyse logs using SQL
  - CloudTrail logs are encrypted with SSE by default
- Can configure a trail to send logs to CloudWatch Logs
  - This can trigger alarms according to metric filters
### Centralisation
- Multi Region Trail
  - --is-multi-region-trail
- Multi Account Trail
  - Must grant cross account permission on S3 bucket
## Security Hub
### Standard findings format
- AWS Security Finding Format
  - ASFF
### Aggregate findings across AWS Organisations
- Use delegated administration via AWS Config aggregators + Security Hub
### Continuously audit AWS usage
- AWS Audit Manager
## Kinesis
### Features
- Analyse data streams in real time
- Collect, transform, process, load, analyse
### Kinesis Data Streams
- GBs of data per second
- Maintain ordering of records
- Multiple data sources
- Multiple consumers
- Use Lambda to process records
  - Invoked as soon as records in the stream
  - Process up to 10 batches per shard
- Retention period
  - 24h default
  - 365 days max
- Common Scenarios
  - Analyse clickstream data in realtime
  - Provide near realtime recommendations
  - Stream score updates to a backend that posts the results on leaderboard
  - Analyse IoT sensor data for predictive maintenance
### Kinesis Data Firehose
- Fully managed service to load streaming data into data stores
- Batch compress and transform data
- Enables data producers to send data to specific destination without custom apps/consumers
- Can automatically encrypt data before uploading
- Use case
  - Sending unstructured log files
    - Kinesis transforms logs using Lambda
    - Transformation failures sent to S3
    - Structured log files sent to Elasticsearch
- Data stores
  - S3
  - Redshift
  - ElasticSearch clusters
- Transformation
  - Invokes a lambda
  - Example: remove sensitive data
### Kinesis Data Analytics
- Analyse and acquire actionable insights
  - Create realtime dashboards
  - Perform time series analytics
  - Analyse results using SQL
- Uses Apache Flink
- Enable author and run code against streaming sources
  - Java or Scala
### Kinesis Video Streams
- Ingest streaming video data from millions of devices
- Store, encrypt, index video data
### Kinesis Resharding
- Pairwise operation
- Adapt to changes in rate of data flowing
- Kinesis Client Library (KCL) tracks the shards using DynamoDB table
  - Must ensure number of instances does not exceed number of shards
## Glue
### Features
- Fully managed ETL service
- Can auto discover data and store metadata
- Job Bookmarking
  - Keep track of where a job left off in case it was interrupted
### Runs in Apache Spark serverless environment
### Glue Data Catalog
- easily search and access data in other data stores
  - Search in S3 or other services
### Glue Studio
- visually create, run, monitor ETL workflows
### Glue DataBrew
- visually enrich, clean, normalise data
- cut down data preparation using no-code tools
### Glue Elastic Views
- use SQL to combine and replicate across data stores
## AppSync
### Create secure, serverless performant GraphQL and Pub/Sub APIs
### Access multiple data sources with a single request
## Lake Formation
### Govern a data lake
### Lake Formation Blueprints
- Automate the process of ingestion
- Incremental DB blueprint loads only new data
### LakeFormation Data Filters
- Specify column level access
### Supports tag based access control
### Integrations
- With QuickSight for dynamic visualisation
- With Athena to query the data in S3
## Endpoints
### Interface Endpoint
- Elastic network interface
  - Private IP
    - Supports IPv4
  - One subnet per AZ
- Entrypoint for traffic to supported service
### Gateway Endpoint
- Target for specific route in route table
  - Same region only
  - Scoped to specific VPC
- Supported service DynamoDB or S3
- Multiple configurations
  - Multi gateway endpoints in single VPC
  - Multi gateway endpoints for single service
    - But needs different reoute tables
### Security
- Optional access policy
  - Specifies access to the service to which you are connecting
### Gateway Load Balancer Endpoint
- Intercept traffic and route to service
- Configuration
  - Choose VPC and subnet
    - Cannot change subnet later
  - Endpoint network interface
    - Private IP
      - IPv4 only
## Trusted Advisor
### Service to analyse AWS environment and provide best practise recommendations
### Basic/Developer plan can access subset of APIs
- Service Limits = all checks
- Security = 6 checks
### Publishes service limit metric to CloudWatch
## Identity Centre
### Centralise identities access to AWS
### Users access roles using AssumeRoleWithSAML
## CloudWatch
### Common Scenarios
- Logs stopped
  - Check agent is active
  - cloudwatch:putMetricData permission
  - Check EC2 instances have internet access
  - Check validity of OS log rotation rules
  - If Lambda check execution role has IAM permission to write logs to CloudWatch
### Concepts
- Namespace
  - Separate data
- Metrics
  - Collection of data points in time ordered structure
- Dimensions
  - Separate datapoints for different things with same metric
  - eg EC2 instance ID and type of instance
### CloudWatch Dashboard
- Global not region specific
### CloudWatch Events
- Consider using EventBridge instead
- Event triggers on operational changes to take corrective action
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
- Define threshold for specific metric
  - OK
  - ALARM
  - INSUFFICIENT_DATA
- Integration options
  - SNS topics
  - Autoscaling
  - EC2 actions
### CloudWatch Logs
- Monitor logs from EC2
  - Default
    - CPU utilisation
    - Disk utilisation
    - Network utilisation
  - Custom
    - Memory utilisation
    - Disk swap
    - Disk space
    - Page file
- Monitor CloudTrail logged events
- Archive log data
- Log route53 DNS queries
- Never expire by default
### CloudWatch Agent
- Needs to be installed
- Collect logs and system metrics from EC2
  - Example use cases
    - Swap/paging utilisation
    - Disk used/free
    - Memory usage
    - Network interface bytes sent/received
    - Processor usage/idle
- Uses Protocols
  - StatsD
    - Supported on Linux and Windows
  - collectd
    - Supported on Linux
### CloudWatch Container Insights
- Collect, aggregate and summarise metrics and logs
- ECS, EKS
## Elasticsearch
### Search, analyse and visualise data in real time
### Service manages capacity, scaling, patching , administration
### Superseded by OpenSearch
## Storage
### S3
- Performance
  - Multi part upload
  - Multiple GB per second
  - Up to 3500 write requests per second
  - Upto 5500 read requests per second
- Features
  - Globally unique bucket names
    - 3-63 characters
    - lowercase
    - no underscores
  - Paths are just prefixed names
  - No POSIX file locking
  - Regional hosting
  - Auto-replicated across AZs
  - Static web hosting
    - Use S3 to host a website
    - Check if need to enable CORS
  - S3 Event Notifications
    - New/Removed/Restored/Replicated
    - Invoke SNS/SQS/Lambda
  - S3 Transfer Acceleration
    - Uses Cloudfront edge locations to optimise transfers
    - Only billed if it improves speed
  - S3 Presigned Urls
    - Work with the permissions of the identity that signs the URL
- Types
  - Standard
  - Infrequent Access (IA)
    - Pricing
      - Min 30 days
      - Charge GB per retrieval
    - Min 30 days in current storage
  - One Zone Infrequent Access
    - Long lived, rapid but less frequent
    - One AZ
    - Pricing
      - Min 30 days
      - Charge GB per retrieval
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
          - Up to 150MB/s
      - Standard
      - Bulk
  - Glacier Deep Archive
- Security
  - Object Lock for Preserving Forensic Evidence
    - Retention Period
      - Fixed time period when object cannot be modified
    - Legal Hold
      - Immutable with no time limit
      - Must remove legal hold
  - Server Side Encryption
    - SSE-S3
      - AWS manages the encryption keys
    - SSE-KMS
      - Customer Managed Key
        - AWS Managed
        - Or, Customer Managed
          - Must be created beforehand
      - Protects against physical theft from AWS datacentres
    - SSE-C
      - Customer provided encryption keys
        - Customer manages the keys
        - AWS uses the key provided in the request
          - Removed from memory after encryption
        - AWS generates a salted HMAC of the key
  - IAM
    - Not public by default
    - Resource based policies
  - Ownership
    - Bucket owner full control
      - Ensure ownership of objects uploaded by external users
- Resilience
  - Use versioning
  - Enable cross region replication
    - Does not replicate existing objects
    - Deletes are not replicated
    - Can be ownde by different account
  - Object Lock
    - Write Once Read Many (WORM)
      - Fixed time or indefinite
  - Optional enforce MFA to delete
- S3 endpoints
  - Interface endpoint
    - Private IP address from subnet range
    - Enable access from on premises
    - Enable access from another region
    - Priced per endpoint
  - Gateway endpoint
    - Specify in route table
    - Does not allow access from on premises
    - Does not support cross region
    - Free
  - S3 Access Point
    - Simplified fine grained access control
    - Can restrict to VPCs
### File Systems
- FSx
  - Types
    - FSx For Lustre
      - High Performance
      - Parallel file system
        - Deployment options
          - Persistent
          - Scratch
        - Can present S3 data with POSIX interface
      - Linux support
      - EKS compatible over CSI
    - FSx for NetApp ONTAP
      - Multi protocol support: NFS, SMB, iSCSI
      - NetApp SnapMirror replicates data eg to DR
    - FSx for OpenZFS
    - FSx for Windows File Server
      - NTFS
      - SMB
      - AD Integration
- Elastic File System (EFS)
  - Fully managed file storage
  - Performance
    - Strong consistency and file locking
    - 10GB+ per second
      - Max I/O Performance Mode
    - Concurrent access across instances
      - 1000s instances
      - Multi region
      - Multi AZ
  - Mount target
    - Network interface
    - Mount command after SSH into instance
      - Or in /etc/fstab
      - Or use SSM Run command
    - Mount target with TLS parameter
    - Mount with IAM authorisation (instance profile)
  - Access Point
  - Class
    - Standard
    - Infrequent access
    - Lifecycle policy
      - Strict last acessed options
        - 0
        - 7days
        - 14days
        - 30days
        - 60days
        - 90days
      - Min 128kb size
  - Backup
    - No native cross region replication
    - Options
      - Use AWS Backup
        - Takes a copy and stores in Vault
        - AWS Backup is priced by amount of storage consumed and per specific services
      - Use AWS DataSync
        - Runs as an agent on an EC2 instance
        - Activated using a browser
        - Requires a VPC peering between source and destination VPC
        - Requires security groups to enable communication
        - Requires VPC endpoint for Datasync in destination region
### Block Storage
- EBS
  - Lowest latency from an instance
  - Single AZ
  - Up to 2GB per second
  - Backup
    - Use snapshots
      - Stored in S3
      - Only available in same region
      - EBS volume can be used while snapshot is in progress
      - Can be copied to different region
        - Can encrypt with different KMS key
  - Types
    - General Purpose SSDs
      - gp2
        - 5.4 million credits
        - max 3000 IOPS (burst) / 250MB/s
      - gp3
        - 20% cheaper than gp2
        - standard 3000 IOPS
          - pay up to 16000 IOPS
    - Provisioned IOPS
      - sub milisecond latency
      - multi attach supported eg Linux based nitro ec2
        - does not support I/O fencing
        - applications must provide write ordering
      - io1
        - more than 16000 IOPs
      - io2
        - more than 64000 IOPs
    - HDDs
      - large sequential IO
      - cannot be boot volumes
      - Cheaper
        - ST1
          - throughput optimised
        - SC1
          - cold
          - cheapest
### Databases
- Aurora
  - Supports
    - MySQL
      - 5x faster
    - PostgreSQL
      - 3x faster
  - Scaling
    - Aurora Serverless allows on demand autoscaling
      - No public IP address
      - Must connect within VPC
      - Features that are not supported
        - Cloning
        - Global databases
        - Multi master clusters
        - IAM DB auth
    - Aurora Parallel Query
      - Fast analytical queries over data
    - Aurora Multi Master
      - Allows multiple DB instances to be read/write
        - Supports up to 4 nodes
      - Compatible with MySQL
      - HA within the same region
    - Aurora Endpoints
      - Reader
      - Cluster
        - Perform write operations
      - Custom
        - eg a particular shared characteristic
      - Instance
        - to a specific DB
    - Max 128TB
    - Auto increase volumes in 10GB increments
  - Availability
    - If deploy an Aurora Replica then Automate failover
      - Recovery Point Objective = 1 second
      - Recovery Time Objective = 1 minute
    - Up to 15 Replicas per region across 3 AZs
    - Global Database can replicate across Regions with <1s latency
    - If no Aurora Replica then best effort DB replacement in same AZ
  - Backup
    - Point in time recovery
  - Security
    - Integrates with IAM, security groups, VPC
    - Encrypt using KMS
      - Uses 1 unique DEK per volume
      - Uses AES-256
      - OS is unaware of encryption
        - Limited performance impact vs FDE
    - Password + IAM auth
    - Automatically patched and updated
- RDS
  - Supports
    - MySQL
      - 64TB
    - PostgreSQL
    - MariaDB
    - Oracle
    - SQL Server
      - 16TB
  - Scaling
    - Increase storage automatically
    - Vertically scale CPU/memory
  - Deployment
    - Single AZ
    - Multiple AZ
      - Standby replica in different AZ
        - Cannot serve read traffic
      - Synchronous replication
      - Auto failover using DNS
    - Read replica
      - Asynchronous replication
      - Supports cross regional
  - Availability
    - Auto replace in event of hardware failure
    - ACID compliant
    - RDS Proxy
      - Fully managed HA DB proxy
      - Automatically connects App to new DB instance
  - Backup
    - User initiated snapshots stored in S3
  - Monitoring
    - Enhanced Monitoring
      - See how different processes or threads use CPU
      - Delivers into CloudWatch Logs
  - Security
    - Integrates with security groups, VPC
    - Encrypt at rest using KMS
    - Encrypt in transit by adding an SSL certificate
      - Force SSL with rds.force_ssl
    - SQL/Oracle supports TDE
    - Password + IAM auth + Kerberos Auth
      - IAM DB Authentication
        - Only MySQL + PostresSQL
        - Not Microsoft SQL
    - Updated on scheduled maintenance windows
- DynamoDB
  - Features
    - Fully managed NoSQL DB
      - Single table by default
      - Primary key = partion key
      - A 'row' in SQL is an 'Item'
      - A 'column' in SQL is an 'attribute'
    - Single digit millisecond performance
    - Serverless
    - Handles millions of requests per second
    - Can auto expire items based on TTL
  - Modes
    - Provisioned Capacity
      - Predictable capacity
      - Min and max thresholds
    - On-demand Capacity
      - Inconsistent patterns
      - Autoscaling
  - Security
    - Can use VPC endpoint for DynamoDB
    - Can protect with IAM policy
  - Performance
    - Improve performance using partition keys with high cardinality
    - Large number of distinct values for each item
  - Backup
    - DynamoDB TTL automatically deletes items after specified timestamp
    - Point in Time Recovery
      - Restore to any point in last 35 days
    - On-Demand Backup/Restore
      - Manual process
  - DynamoDB Global Tables
    - Identical tables in different regions
    - Writes are propagated globally
    - Requires streams to be enabled
    - Uses IAM role AWSServiceRoleForDynamoDBReplication
  - DynamoDB Streams
    - Can associate the ARN with a Lambda function
  - DynamoDB Transactions
    - Offers read/write API that is atomic
  - DynamoDB Accelerator (DAX)
    - Microsecond response time
    - In memory cache
      - Item cache
        - GetItem
        - BatchGetItem
        - TTL = 5min
      - Query cache
        - Query and Scan operations
        - user specified TTL
    - Preferred caching solution
    - Limitations
      - Doesnt support TLS
      - Only supports languages
        - Go
        - Python
        - Node.js
        - Java
        - .NET
      - Cannot manage the cache invalidation
- Redshift
  - Features
    - Fully managed data warehouse
    - Structured data
    - Analyse using SQL
    - Intended for OLAP
  - Redshift Spectrum
    - Query structured and semistructured data from S3
    - Serverless
  - Deployment
    - 1 leader node
      - Receives queries
      - Coordinates parallel execution
      - Collects results
    - 1or more compute nodes
  - Availability
    - Auto replaces any failed node within cluster
  - Backup
    - Replicates data within cluster
    - Continuous backup to S3
- Elastic MapReduce (EMR)
  - BigData cluster
    - Hadoop
    - Spark
    - Hive
  - Place Task nodes on spot instances for lower cost
  - Elastic Scaling
    - Multiple clusters
    - Resize running clusters
    - Autoscale
  - EMR Serverless
    - Does not support Apache Ranger
- ElastiCache
  - Redis
    - Security
      - Enable Redis AUTH
      - Enable encryption In Transit
        - --transit-encryption-enabled
  - Memcached
    - Supports Auto Discovery
      - Enables client to identify all nodes
    - Failed nodes automatically replaced
- Athena
  - Simple way to query data in S3
  - Data returned in a table
  - Storage improvements
    - Compress eg GZIP
  - Performance improvements
    - Use Parquest or ORC file formats
      - Supports predicate pushdown
- DocumentDB
  - MongoDB compatible DB
  - NoSQL
  - Json format
- Keyspaces
  - Cassandra compatible DB
  - Wide column data store
- Neptune
  - Graph DB
- Timestream
  - Serverless time series database service
  - Suitable for IOT and operational applications
- QLDB
  - Ledger database
  - Transparent and immutable transaction log
- Database Migration Service (DMS)
  - Cloud service that makes it easy to migrate DBs
  - Performs one time migrations and can replicate ongoing changes
  - Can be secured using TLS by providing a Certificate
- AWS Schema Conversion Tool (SCT)
  - Convert your existing DB schema from one to another
  - Suitable for RDS, Aurora, Redshift
### Storage Gateway
- File Gateway
  - S3 File Gateway
    - Download a VM image
      - Hardware appliance also available
    - Create and configure a fileshare to an S3 bucket
    - Supports clients via NFS or SMB
  - FSx File Gateway
    - Requires 1 or more FSx for Windows File Server
    - Requires on premise access via VPN/DC
    - Runs on a downloaded VM or Hardware appliance
    - Example create an SMB file share mounted on Windows instances authenticated with AD
- Volume Gateway
  - Block storage via iSCSI to store into S3
  - Can generate EBS snapshots usable by EC2
- Tape Gateway
  - Cloud based virtual tape library to store into S3
- On-Premise hybrid cloud options
### Snowball
- Edge
  - Petabyte scale data transport
    - Up to 80TB storage
  - Uses secure appliances to transfer data
    - Stored into S3
    - Can be clustered
- Snowmobile
  - Exabyte scale data transfer
    - Up to 100PB
    - Recommended for 10PB or more
- Snowcone device
  - Collect files from storage system
  - Help preserve existing file permissions
  - Combine with Datasync agent and FSx for Windows
### DataSync
- Simplifies transferring large quantities of data
  - Can saturate 10Gbps link
  - Encrypts in transit
  - Performs a file integrity check
- Deploy a DataSync agent
  - On Prem
  - In AWS
- DataSync supports
  - NFS, SMB
  - EFS
    - FSx for Windows
  - S3
  - Supports VPC endpoints
- Mode
  - Transfer only data that has changed
  - Transfer all data
## Elastic Disaster Recovery (DRS)
### Assists in performing a failover to AWS for immediate recovery
### Uses a replication agent
## Well Architected Framework
### Security
### Reliability
### Performance
### Operational Excellence
### Cost Optimisation
### Sustainability
## Workspaces
### Virtual desktops
### Workspaces Secure Browser
- Protected environment for access to private websites / SaaS
- Provide sandbox access to web based GenAI
## Wavelength
### Embeds AWS compute and storage into teclo datacentres at edge of 5g network