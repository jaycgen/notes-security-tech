# GCP Basics
## IaaS
### Pay for the resources they allocate ahead of time
## PaaS
### Pay for the resources they actually use
## Serverless
### Cloud Functions
- Event driven code as pay as you go
### Cloud Run
- Deploy containerised microservices in fully managed environment
## Security
### Hardware infrastructure layer
- Custom designed server boards and networking
- Custom hadware security chip
- Secure boot stack
- Premises security
### Service Deployment layer
- Encryption of inter service communication
  - Cryptographic RPC traffic
  - Hardware crytographic accelerators
### User identity layer
- Device fingerprint
- U2F
### Storage services layer
- Encryption at rest
### Internet communication layer
- Google Front End
  - TLS
  - PFS
  - DoS protection
### Operational security layer
- Intrusion detection
- Reducing insider risk
- Employee U2F use
- Software development practises
## Google Global Network
### 5 major Geographic Locations
- North America
- South America
- Europe
- Asia
- Australia
### 40 Regions
### 121 Zones
## Billing
### Per second billing
### Discount when running significant % of month
### Online pricing calculator
### Define budgets at project or billing account level
- Alerts can be set and customised
### Define quotas at project level
- Rate quotas
- Allocation quotas
## IAM
### Who = principal
- Google account
- Google group
- Service account
- Cloud identity domain
### What = role
- Collection of permissions/policies
- Basic roles
  - Owner
  - Editor
  - Viewer
  - Billing Admin
- Predefined roles
  - eg Instance Admin Role
- Custom role
  - Only defined at project or organisation level
### Policy precedence
- Deny first
### Service Accounts
- Named with email address
- Can have IAM roles
### Cloud Identity
- Define policy and groups
- Sync with existing directories
## Resource hierarchy
### Organisation node
- Folder
  - Project
    - Resources
### Projects
- ProjectID
  - Immutable
- Project Name
- Project number
### Folders can contain folders
- Enable delegating admin rights
- Inherit policies from folder
### Organisation node
- Org policy admin
- Project creator role
## Networking
### VPC
- Private secure cloud
- VPC networks span zones in regions
  - Resources can be in different zones on the same subnet
- Segment networks
- Connecting VPCs
  - Shared VPC
  - VPC peering
  - Cloud VPN
    - Uses Cloud Router
    - Uses BGP
      - Means can add a subnet to Google VPC and on premises network gets routes to it
  - Direct Peering
    - Put a router in same public data centre as Google point of presence and use it to exchange traffic between networks
    - Carrier peering
    - Dedicated Interconnect
    - Partner Interconnect
    - Cross Cloud Interconnect
      - Peer with another public cloud
        - Subtopic 1
      - 10Gbps or 100Gbps
- Routing tables
  - Forward traffic
- Firewall
  - Rules can be set on tags
- Cloud Load Balancing
  - Global HTTPS
  - Global SSL Proxy
  - Global TCP Proxy
  - Regional External Passthrough
    - eg UDP or any port number
    - Can also deploy
      - Regional External Application Load balancer
      - Proxy Network load balancer
  - Regional Internal
    - Supports
      - Proxy network load balancer
      - passthrough network load balancer
      - application load balancer
  - Cross region internal
    - Layer7
    - Directs to closest backend
- Cloud DNS
  - Managed DNS
- Cloud CDN
  - Easy to enable with application load balancing
## Compute Engine
### Virtual machine instance
- Linux or Windows provided by google
- Cloud Marketplace
- Pricing
  - 57% Committed discounts 1/3yr
  - Discount if running more than 25% month
  - Preemtible
    - Can only run for max 24h
  - Spot VMs
### Scaling
- Autoscaling
## Storage
### Cloud Storage
- Object Storage
  - Stored in packaged format
    - Binary form of the actual data
    - And associated metadata
    - And global unique identifier
  - Common formats
    - Video
    - Pictures
    - Audio recordings
    - Website content
- Organised as buckets
  - Global unique name
  - Specific region
- Versioned
- Lifecycle managed
  - eg delete older than
  - eg only keep x versions
- Permissioned
  - IAM
  - ACL
- Classes
  - Hot
  - Nearline
    - Once per month
  - Coldline Storage
    - Once every 90 days
  - Archive Storage
    - Once a year
  - Autoclass feature
- Storage Transfer Service
  - Schedule and manage batch transfers
### Cloud SQL
- Relational databases
  - MySQL
  - PostgreSQL
  - SQL Server
- Automatic replication
- Encrypts customer data
### Spanner
- Fully managed relational DB
  - Highly scalable SQL
### Firestore
- NoSQL
  - Document storage with subcollections
  - Key value store
  - Indexed by default
### Bigtable
- NoSQL big data service
- Massive workloads at low latency high throughput
- Data integration
  - Dataservice layer
    - Read/Write via managed VMs
    - HBase REST
  - Data streaming
    - Dataflow Streaming
    - Spark Streaming
    - Storm
  - Batch processes
    - Hadoop MapReduce
    - Dataflow
    - Storm
## Interacting with GCP
### Console
- Web based
### Cloud SDK and Cloud Shell
- Google Cloud CLI
- CloudShell is debian based web browser
### APIs
- Google API Explorer
- Cloud client libraries
  - Java
  - Python
  - C#
  - Go
  - Node.js
  - Ruby
- Googleapi client
### Google Cloud app
- Start/Stop/SSH
- View logs
- Administer apps on App Engine
  - View errors
  - Roll back deployments