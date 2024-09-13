# Subdomain Takeover Basics
## Problem statement
### Process of registering a non-existing domain name to gain control over another domain
### Implications
- Send phishing emails from the legitimate domain
- Perform XSS
- Damage the brand reputation
## Common Scenario
### Dangling CNAME
- Source
  - sub.example.com
- Uses a CNAME record to another domain
  - anotherdomain.com
- The canonical domain name expires
### NS records
- Specifies the authoritative name server for the domain
- Multiple NS records for redundancy might mean % chance of takeover
### MX records
- Allows receiving emails
### A records
## Detection
### Start
- Domain names
### Extract base domain from canonical domain name
### Check if base domain is available for registration
### If yes, takeover possible
## Use cases
### SaaS/Cloud
- shop.organisation.com vs organisation.saas-provider.com
- How to redirect
  - HTTP 301/302 redirect
  - Or, CNAME record
### Cloudfront
- Distributions
  - get auto generated subdomain.cloudfront.net
  - Can specify an alternate domain name
    - Requires a CNAME record from alternate to cloudfront subdomain
  - Subdomain takeover
    - If CNAME sub.example.com is set but not registered in distribution as an alternate domain name
    - And if the distribution is not disabled