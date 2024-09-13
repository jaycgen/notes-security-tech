# Kubernetes OWASP Top 10
## Control Plane
### Controller
- Vulnerable K8s Components
  - Patch and upgrade
### Scheduler
### etcd
- Secret Management
  - Encrypt secrets at rest
  - Address security misconfigurations
  - Use well defined access control
  - Ensure logging and auditing
- Misconfigured Cluster Components
  - Backup to avoid data loss
- Vulnerable K8s Components
  - Patch and upgrade
### Istio
- Network Segmentation
  - Use a service mesh
  - Enforce network policies
- Vulnerable K8s Components
  - Patch and upgrade
### K8s API
- Overly Permissive RBAC
  - Enforce least privilege clusterroles and roles
  - Scan and audit RBAC
- Policy Enforcement
  - Centralise Enforcement
  - Use Admission Controllers
  - Use Runtime detection
- Inadequate Logging
  - Kubernetes Event Logs
- Broken Authentication
  - Avoid using certificates for end users
  - Enforce MFA where possible
  - Dont use ServiceAccount tokens outside the cluster
  - Authenticate users and external services using short lived tokens
- Misconfigured Cluster Components
  - Enable TLS
  - Rotate Certificates
- Vulnerable K8s Components
  - Patch and upgrade
## Workers
### Ingress
- Inadequate Logging
  - Network Logs
### kube-proxy
- Vulnerable K8s Components
  - Patch and upgrade
### kubelet
- Misconfigured Cluster Components
  - Prevent Anonymouse Authentication
- Vulnerable K8s Components
  - Patch and upgrade
### Pod
- App1
  - Insecure Workloads Configurations
    - App processes should not run as root
    - Read only filesystems
    - Disallow privileged containers
    - Use minimal base impages
    - Audit workloads
    - Use Admission Controllers (eg OPA)
  - Supply Chain Vulnerabilities
    - Verify image integrity
    - Assess image composition
    - Mitigate known software vulnerabilities
  - Inadequate Logging
    - Application and Container Logs
- App2
  - Insecure Workloads Configurations
    - App processes should not run as root
    - Read only filesystems
    - Disallow privileged containers
  - Supply Chain Vulnerabilities
    - Verify image integrity
    - Assess image composition
    - Mitigate known software vulnerabilities
  - Inadequate Logging
    - Application and Container Logs
- Network Segmentation
  - Enforce network policies
## Container Runtime
### Vulnerable K8s Components
- Patch and upgrade
## OS
### Supply Chain Vulnerabilities
- Verify o/s integrity
- Assess o/s composition
- Mitigate known software vulnerabilities
### Inadequate Logging
- Operating System Logs
- Cloud Provider Logs
### Vulnerable K8s Components
- Patch and upgrade
## Container Registry
### Supply Chain Vulnerabilities