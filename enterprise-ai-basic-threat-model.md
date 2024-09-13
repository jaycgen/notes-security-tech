# Enterprise AI Basic Threat Model
## Focus
### Business risk and business productivity
### Communicate the risk, tradeoffs and controls
## Risk Analysis
### Do tools align with Compliance standards
### What operational costs will this incur
### What people and control investments need to be made before go-live
### Are there thresholds of tools or data that cant be connected
### Whats the viability of the product and ROI
### Define and Document
- Applications to integrate
- Data and Classification
## Cloud or On Prem
### Self Hosted
- Understand operational cost
- Implications for long term support
- Reduce surface area
### SaaS
- Understand vendor access to your API keys
### Self build
## Connected SaaS Applications
### Confidence in storing confidential data
### Describe applications to integrate
### Consider classification and risk of data
### Understand cost-benefit tradeoff
## Control Levers
### Access Control
- Who
- How
- What devices
### Integrations
- Connect vs block
### Detections
- Malicious activity
## Top Risks
### Zero Trust Bypass
- Potentiall bypass of AuthN/AuthZ
### Supply Chain Compromise
- Vendor open route to your data
### Overly permissive access
- Misconfigured elevated access to data
- More easy discovery of existing control failures
### Synchronisation delays
- Increasde latency to remove data/access
### Privacy
- Exposure to administrators
### Session Token Theft
- Increased attack surface
### AI Training
- Intellectual property risk of training data