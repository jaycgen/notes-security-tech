# AWS Lambda
## Layers
### Modular packages attached to lambda functions
### Add additional resources or libraries without changing lambda function code
### Layers can be published and shared publicly
### Layers must be formatted as Zip archives
### Contents are unzipped into lambda execution env at runtime
## Extensions
### Allow modules to deploy and execute within lambda execution envs
### Internal extensions
- Packaged as part of lambda function code package
### External extensions
- Deploy dynamically via AWS API
  - UpdateFunctionConfiguration
- Typically packaged within a lambda layer
## Fetch Secrets Extension
### Square: Lambda Secrets Prefetch
## Lambda internals
### Physical
- Firecracker
  - Open source microVM framework
  - UsesKVM to create microVMs
### Rapid
- Lambda function booted with single custom init process
- init process written in Go
### Rapid API
- runtimes communicate with the Rapid process through a local HTTP server
- Local Procedural Calls
- typically set to http://127.0.0.1:9001
- HTTP endpoint examples
  - Next invocation event
  - Return value from lambda function handler
  - Register extensions
### Open File Descriptors to Sockets
- Telemetry
- Logs
- Control Sockets
### Function
- Runtime
  - Filesystems
    - all filesystems are readonly except for /tmp
    - /tmp directory persists between invocations of same function
    - Extensions at /opt/extensions/{{extensionName}}
  - Event Polling
    - Runtimes receive new Lambda invocation events by sending requests to the Rapid API
    - Once events are processed, runtimes are expected to post an HTTP response to this same endpoint
    - Rapid exposes multiple HTTP endpoints that allow runtimes and extensions to receive events and send responses
## Lambda threats
### Backdoor after RCE
- Modify bootstrap file
- Write malicious bootstrap to /tmp
- Get current request ID from Rapid API
- POST request to end current event
- Swap system runtime to malicious bootstrap
### Read IAM credentials via file vuln
- read from /proc/self/environ
- vulns
  - SSRF
  - XML external entity
### Extension Merge order hijacking
- Last layer to merge wins
- Avoid untrusted layers
- Malicious supply chain attack