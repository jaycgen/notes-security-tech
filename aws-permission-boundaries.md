# AWS Permission Boundaries
## What are they
### IAM policies that can be attached to principals
### Limit the maximum permissions
### Can only deny
- through absence of allow
- or through explicit deny
## Use cases
### Enable self service builders
### Constrain delegation to a boundary
## Guidance
### Do not put resources in boundary policies
- Use wildcards for course grain access
### Only use allow statements
### Avoid using conditions
- Better in SCPs or Resource Policies
### Avoid having unique boundary per role
### Ensure boundary policies are used
### Use IAM paths to constrain access