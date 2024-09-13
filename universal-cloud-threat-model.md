# Universal Cloud Threat Model
## Attack Vectors
### Credentials
- Lost
  - Phishing
  - Compromised PATs
- Stolen
  - Infostealer
- Exposed via humans
  - Committed to git repos
- Exposed via application flaws
  - SSRF
    - Mitigations
      - WAF
      - IMDS v2
      - Least privilege
- Mitigations
  - Avoid long term keys
    - Dont use IAM users
    - Federate users with SSO
  - MFA
    - Opt for phishing resistent MFA
  - Control privileged access
    - Just In Time access
### Publicly exposed resources
- Missing resource policies
- Overly permissive policies
- Lack of authentication
- Misconfigured network
- Mitigations
  - Prevent invariants
    - Apply Service Control Policies
    - Support rapid exceptions
  - Monitor the perimeter
    - Minimise internet facing surface
  - Govern a data perimeter
  - Maintain good cloud hygiene
    - Remove unneeded resources
    - Assign least privilege and short TTL credentials
    - Apply secure by default configurations
  - Auto-remediate high risk
### Vulnerabilities
- Unpatched
- Zero days
- Mitigations
  - Scan code
    - Identify vulnerabilities
    - Find exposed secrets
  - Reduce the blast radius of applications
    - Avoid highly privileged IAM roles/policies
    - Protect the metadata service
    - Use a WAF to mitigate application layer attacks
    - Detect and manage using runtime protection
      - Cloud Workload Protection
      - Kubernetes Runtime protection
      - Container Security Platform
  - Govern the supply chain
    - Use known and trusted sources
      - Base images
      - Libraries
    - Pull resources from reputable sources
      - Package managers
      - Cache inside organisation
    - Scan for malicious and outdated software
      - Manage SBOMs
### Denial of Service Attacks
- Mitigations
  - Plan for DoS
    - Minimise internet exposure
    - Leverage insulating services
      - CDN
      - Loadbalancer
### Subdomain takeover
- Resources de-referenced
- Underlying resources deleted
- Mitigation
  - Automatically scan for dangling DNS
    - Domain monitoring
### Supply chain compromise
- Injected malicious backdoor
- Mitigations
  - Use only trusted source base images
  - Pull packages from official sources
  - Cache software inside the organisation
  - Scan for provenance
## Foundation
### Asset Inventory
### Backups
### Visibility of logs and events
### Plan for remediation
### Improve alerting and scanning
## Prioritisation
### Discoverability * exploitability * impact = Priority