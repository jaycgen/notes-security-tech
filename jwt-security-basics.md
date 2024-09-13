# JWT Security Basics
## What is a JWT
### JSON Web Token
- Base64 encoded json objects
### 3 Parts
- Header
- Payload
  - Contains the claims
  - Common claims
    - iss
      - Issuer of the JWT
    - exp
      - Expiration timestamp
    - sub
      - Subject of the JWT (user)
    - aud
      - Intended recipient of JWT
    - iat
      - Issued At Time
        - Use to determine age
    - jti
      - Unique identifier
        - Use to prevent replay
    - nbf
      - Not before timestamp
    - role
    - email
- Signature
- Separated by dots
## Refresh Tokens
### Refresh Token Rotation
- every time an application exchanges a refresh token to get a new access token, a new refresh token is also returned
### Automatic reuse detection
- IDP keeps track of refresh tokens
  - Token family
- Detect out of sequence use of a refresh token
  - Invalidate the family
  - Prompt for reauth
## Flawed JWT Signature Verification
### Fail to verify
- If only decode token
- If use none existing algorithm
### Accept malicious signatures
- If trick server to use wrong algorithm
  - Switch Asymmetric for Symmetric
- If inject malicious jwk
  - Embed attacker key in token
- If inject attacker controlled jku URL
- If kid is vulnerable to injection or path traversal
### Guess secret key
- If weak signing key
  - Brute force
  - Insecure default
## Guidance
### Always send tokens over HTTPS
### Avoid sending tokens in URL parameters
### Always set a token expiration
### Always include and validate audience claim
### Enable the server to invalidate/revoke tokens