# Cloud IAM access to K8s
## Functional Requirements
### Make it easy for engineers to start a session
### Cloud access
- AWS
  - EKS
    - AWS CLI
      - Engineers can run AWS cli tools to read, create and update information about clusters
        - Create an EKS cluster
          - aws eks create-cluster --name my-cluster --role-arn <role-arn> --resources-vpc-config subnetIds=<subnet-ids>,securityGroupIds=<sg-ids>
        - Use kubectl with an EKS cluster
          - aws eks update-kubeconfig --name my-cluster --region us-west-2
    - Create 1x access entry for 1x cluster to 1x AWS IAM Role
      - aws eks create-access-entry
      - Create associations from 1x IAM role to 0 or more EKS Access Policy
        - eks cluster-access-policy
          - AmazonEKSViewPolicy
          - AmazonEKSAdminPolicy
      - Create associations from 1x IAM role to 0 or more K8s Groups
        - Create ClusterRole with perms
        - Map ClusterRole to K8s Group
- GCP
  - GKE
    - gCloud
      - Engineers can run GCP cli tools to read, create and update information about clusters
        - Create a GKE cluster
          - gcloud container clusters create my-cluster --zone us-central1-a
        - Use kubectl with a GKE cluster
          - gcloud container clusters get-credentials my-cluster --zone us-central1-a
    - Create N Google Groups
      - Create K8s Role Binding that has a K8s Group. This should reference and maps to the Google Group
### K8s access
- Clusterroles
- Namespace roles
- Engineers can run K8s cli tools like Kubectl to read, create and update resources on clusters
## Security / Regulatory requirements
### Least Privilege
- Why
  - BAU development
  - BAU maintenance
  - onCall support
  - breakglass privilege
- Who
  - Integrated with JML
    - only certain Role/Groups
  - Strong Auth
    - MFA
    - Step up MFA
  - self service anyone can request
- When
  - Time Limited
  - Any time?
  - Only Office Hours?
  - Only when onCall?
- What
  - Right amount of privileges
    - Non production
    - Production
    - Customer data
  - Decision about precanned vs dynamic
- How
  - Decision about access control matrix
  - Decision about approvals
### Secure network access to K8s
- Public with AuthN
- Public with restricted CIDR
- Private VPC with VPN
### Auditable
- Logs
- Notifications
  - Integrations
    - Slack
    - JIRA
  - Approvals
- Review/report access on demand
## Scalability Requirements
### Automatically cover new employees
- Use/synchronise data from existing employee directory
### Automatically enrol new clusters
- Can import cloud data?
- Is cloud data reliably tagged?
## Scoping
### Build vs Buy
- Britive
- Apono
- Teleport
- ConductorOne
### How many engineers
### Need to cover non employees?
- Vendors
- Contractors
- Customers
### How many Cloud accounts
### How many clusters
### Self managed or cloud managed? eg EKS
### How often access
### Access Cloud vs K8s vs both
### Authentication
- Is it also the Identity Provider
- Is it an App integrated with existing IDP
- Identity Provider choice
  - Cloud IAM
  - External OIDC IDP
    - eg Build own
    - eg Okta
### Authorisation
### Accounting
### Front door UX?
- Is it a service catalogue
- Is it an ownership inventory