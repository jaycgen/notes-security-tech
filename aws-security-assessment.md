# AWS Security Assessment
## Core Principles
### Breadth then depth
- Context to inform prioritisation
### Anomaly detection
- Exercise in pattern matching
### Inside out
- SecurityAudit or ReadOnlyAccess
  - Enumerate and query
### Outside In
- Emulate the attacker
  - Exposed resources
  - Attack surface discovery
## Corporate Archeology
### Asset Inventory
### Intended practises
- Configuration as code
- Authentication and identity
### Data classification
- Definecrown jewels
### Tagging practises
## Prioritisation
### Threats
- Initial Access
  - Static API credential exposed
  - Compromised service exposed to internet
    - Server
    - Database
    - Object Storage
  - Network attack
  - SSRF
  - Malicious supply chain
  - Cloud data exposure
- Other
  - Cryptomining
  - Compromised Secrets
  - Subdomain takeover
### Identity Perimeter
- Management plane access model
  - Organisations
  - IDP Provisioning
  - MFA
  - Temporary access keys
- SSH/Server access model
  - Exposed SSH
  - Bastions
  - Cloud native
- Least privilege
  - Secure root user
  - Cleanup unused roles and users
- Audit
  - Native
    - IAM Credential Report
    - IAM Access Analyzer
    - Trusted Advisor
    - AWS Config
  - Open Source
    - Cloudsplaining
      - Risk prioritised report on violations of least privilege
    - PMapper
      - Script to identify privesc risks with IAM graph
    - PolicySentry
      - Improve UX of least privilege policy generation
    - RepoKid
      - Toolto reduce permissions based on usage
### Network Perimeter
- Public resources in managed services
- Public network access to hosted services
- Default insecure resources
  - Default VPCs
  - Security groups with launch-wizard
### Hosted Applications and Services
- Out of date vulnerable services
- Unauthenticated services
- Sensitive services that are public
### Less actionable
- Default cloudformation parameters
- Unencrypted Lambda ENV variables
- EC2 instance data with hardcoded secrets
- ECS Task definitions with exposed ENV variables
- Sensitive files on S3
- Docker/container images
- CodeRepos and compromised credentials
## Roadmap
### Enable GuardDuty in all accounts
- Centralise alerts
### Enable CloudTrail in all accounts
- Centralise trail
- Enable encryption and file validation
- Backup logs
### Security visibility of all accounts and breakglass
### Organisation wide secure default
- Block S3 public
- EBS Encryption
## Discovery
### Environments
- Find all AWS accounts
  - Inventory known accounts
  - Ask Technical Account Manager to identify associated with company domain
  - Search emails for Welcome to Amazon Web Services
  - Search network logs for traffic to AWS Console
  - Find all expenses to cloud providers
  - View trust relationships from identified accounts
  - Ask employees
- Inventory relationship between Accounts and Organisations
### Workloads
- Start with Billing Reports
  - Find architectural patterns
### Resources
- Index across the cloud estate
  - Leverage existing company tooling
    - CSPM
    - Service Provider tools
      - Security Hub
      - AWS Config
  - Run auditing tooling
    - Steampipe
    - Prowler