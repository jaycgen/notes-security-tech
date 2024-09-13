# Lambda
### Decide between Signed URL and Signed Cookies
### Generate a Signed URL
- Choice
  - Canned Policy
  - Custom Policy
  - Optional start time
  - Optional IP restriction
- Requires
  - Private Key to sign
- Structure
  - CloudFront Domain Name
  - S3 Resource Path
  - Epoch Time of Expiration
  - Signature Generated via Private Key
  - Cloudfront Public KeyID
- Libraries
  - boto3
    - s3.generate_presigned_url
### Signing Pre-Reqs
- Lambda Function IAM role
  - Fetch the Private Key and ID from Parameter Store
## API Gateway
### Create an API
- Trigger invoking Lambda
## Parameter Store
### Store the Private Key used for signing
- Protect Parameter with KMS CMK
### Store the Cloudfront distribution domain
### Store the Cloudfront keypair ID
## Aurora
### Store Metadata
- Customer identifier
- Customer path within S3
- RBAC expectations on file
## CloudFront
### Create Cloudfront distribution
- Origin Settings
  - Add a custom header
  - Associate the Origin Access Control
  - Enable Origin Shield
- Cache Behaviour
  - Specify the origin
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
## WAF
### Associated with CloudFront
### Define WebACL
- Manage via Firewall Manager
## Cognito
### Enforce authentication
- User Pool
  - Federate with external Identity Provider
  - Obtain a JWT with customer identifier
## S3
### Protect Unauthorised Access to Bucket
- Enable SSE-KMS
- Block public access
- Bucket Resource Policy
  - Allow Principal Service
    - cloudfront.amazonaws.com
  - Allow S3 Actions
  - Condition StringEquals SourceArn
    - cloudfront distribution ARN
### Protect data in transit
- Enforce HTTPS
- Enable CORS if using custom domain
## KMS
### Customer Managed Keys
- Key Policy for SSE-KMS
  - Allow Principal Service
    - cloudfront.amazonaws.com
  - Allow KMS Actions
  - Condition StringEquals SourceArn
    - cloudfront distribution ARN
- Key Policy for ParameterStore
  - Allow Principal Service
    - lambda
  - Allow KMS Actions
  - Condition StringEquals SourceArn
    - lambda execution role arn
## Client
### Makes request to API Gateway
- Upload URL
  - Get a pre-signed URL
- Download URL
  - Get a pre-signed URL
### Authenticates via Cognito
### Uploads directly to S3 using presigned URL
### Download directly from S3 using presignde URL