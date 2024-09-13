# GitHub Security Basics
## GitHub Actions
### Protect .github/workflows with codeowners
### Mitigate risk of untrusted input
- context
  - body
  - ref
  - title
  - message
  - branch name
- use an action instead of inline script
- use an intermediate environment variable
### Avoid long lived static credentials by using OIDC
### Govern 3rd party actions
- Audit the action source code
- Pin to full length commit SHA
- Pin to tag only if trust creator
- Use Dependabot to keep actions up to date
- Vulnerable supply chain even with pinning
  - If 3rd party action uses container with mutable tag eg latest
  - If 3rd party action builds or runs a contaienr with unpinned dependencies
  - If 3rd party action depends on another 3rd party action without pinning
### Use OpenSSF Scorecards
### Dont use self hosted runners for public repos
### Discourage use of pull_request_target
### Use least privilege GITHUB_TOKEN permissions for workflows
- use 'permissions' key in workflows to restrict access further
### Dont allow Github Actions reviews to count towards approval
## GitHub Apps
### Use a github app in a github actions workflow
- Register GitHub app
  - Choose permissions
- Store app ID of GitHub App in GitHub Actions configuration variable
- Generate private key for app
  - Store as a secret
- Install GitHub App on account or organisation
  - Grant access to repos
- Create installation access token in Github Actions workflow
  - eg actions/create-github-app-token
## Artifact attestations
### Generate attestations for builds
### Generate attestations for SBOMs
### Verify attestations with GitHub CLI
## Secrets Protections
### Use environments
- Trust concrete branches vs branch protetions
- Require admins to approve environment access
### Redaction by default
### Register secrets within workflows
### Audit secrets
- Review the source code of the repository executing the workflow
- Viewthe run logs for workflows
### Use minimal scoped credentials
### Any user with write access to repo has read access to all secrets configured in repo
## Repo Protection
### Repository Rulesets
- Upto 75 rulesets per repo
  - Restrict file paths
    - eg.github/workflows/**/*
  - Restrict file path length
  - Restrict file extensions
  - Restrict file size
  - Restrict creations/updates/deletes
    - branches
    - tags
  - Require linear history
    - Squash merge or rebase merge
  - Require deployments to succeed before merging
  - Require signed commits
  - Require status checks to pass before merging
  - Set code scanning merge protection
  - Block force pushes
  - Require code owner review
  - Require last push approval
  - Dismiss stale reviews on push
  - Required approving review count
- Can be bypassed by named users or teams
- Canbe applied at organisation level
### Branch Protections
- Avoid wildcard branch protections
  - Protect who can create matching branches