# Authorization Code Flow with Proof of Key Exchance PKCE
## User
### Clicks Login
## App
### Auth Library
- Creates a crypto random code verifier
- Generates a code challenge
### Redirects User to IDP /authorize
- Sends the code challenge
## Identity Provider
### Checks if already authenticated
### Prompts user with consent options and to login
## User
### Views Consents and Login
### Submits credentials to IDP
## Identity Provider
### Validates user credentials
### Stores the code challenge
### Generates authorization code
### Redirects the user back to application
- Sends the auth code
## App
### Auth Library now has auth code and code_verifier to IDP
### Sends those to IDP
- /oauth/token endpoint
## Identity Provider
### Verifies
- code challenge
- code verifier
### Generates Tokens
- ID token
- Access Token
### Responds with tokens to the App
## App
### Auth Library now has Access Token
### Can use token to call API
## API