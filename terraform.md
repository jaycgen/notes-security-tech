# Terraform
## CICD
### Terraform Cloud
- Commercial cost
- Feature rich
  - Sentinel
  - Module registry
  - Remote execution backend
    - Upload local and run plan
### Atlantis
- Opensource
- Self hosted
- Runs on 1 VM
### Spacelift
- Commercial
- Features
  - OPA policies and checks
  - Customise workflow and add tools
  - Stack dependencies to deploy in one go
  - Run commands using tasks with state to import/move/remove
  - Driftdetection
### Digger
- Runs in own CICD
- Opensource + paid
- generate_projects
  - In digger.yml
    - Specifies include and exclude path patterns
### Patcher
- From terragrunt
## AWS Recommendations
### Create an account vending machine
- Self service experience to get a new account
- Kickoff workflow
  - e.g. manual github action
- Prompt for user data
- Generate code to trigger AWS Control Tower
- Raise PR
- Run Terraform apply using cicd
### Use AWS Control Tower
### Create a Landing Zone
- Additional guardrails
- Encryption defaults
- Networking
- Auth
  - OIDC
  - SSO
### Code Foundations
- Use infra from a catalogue
  - e.g. Gruntwork library
- Use Terraform to manage everything as code
- Deploy infra via scaffolding and gitops
### CICD Foundations
- Translate git into infrastructure operations
- Modify terraform = module update
- Remove directory = module delete
- IaC Workflows
  - plan
    - output as a PR comment
  - apply
    - after merge
  - destroy
    - plan -destroy
    - destroy after merge
- Federate identity using OIDC
  - machine users
  - dynamic credentials
  - Create OpenID Connect Provider for Github Actions
    - Define the allowed organisations
  - Create IAM Roles and Assume Policies to be used by Github Actions
    - Define the URL
      - Use the enterprise slug if exist
    - Define the thumbprint list
    - Create the IAM role
      - Define the allowed sources
        - organisation
        - repo
        - branch
  - Create GitHub Actions Workflow
    - Attach permissions to write id-token at the workflow or job level
    - Add aws-actions/configure-aws-credentials to the step
    - Specify
      - role-to-assume
      - role-session-name
      - aws-region
- Isolated workers
  - Limit approved commands
- Protect version control
  - Branch protection
  - Ensure review
- Approval workflows
  - Require relevant teams/users
- Access Controls
  - Restrict who can change what
- Automated tests
  - Linting
  - functional tests
  - security analysis
### Maintenance Foundations
- Release new module versions
- Use automated updates
  - Version bumps
- Use automated patching
  - Patch to transform breaking changes
- Progression workflows
  - Auto update dev
  - Auto update stage
  - Auto update prod
## Managing Modules
### Put into 1 or more git repos of their own
### Invoke them
- module "name_of_module" {
            - source          = "../../path/to/module"
            - ad_group_names  = var.groups_list
          - }
## Structure
### live
- main.tf
- outputs.tf
- data.tf
- variables.tf
### environments
- example
  - terraform.tfvars
  - backend.hcl
## Coding Practises
### Avoid Hard Coding Variables
- Use data to pull from an external source
  - data "aws_caller_identity" "current" {}
- Define variables as locals
  - locals {
              - hostname_db_vm      = "my-db-vm"
              - location            = "westeurope"
              - resource_group_name = "test_rg"
            - }
### Use variables
- bucket = "example-bucket-${random_pet.name.id}"
- region = var.aws_region
- name                = "${local.hostname_db_vm}-nic"
- location            = module.settings.location
### Format and Validate
- terraform fmt
- terraform validate
### Naming Convention
- lowercase letters
- underscores as separator
- trynot to repeat resource type
### Tag resouces
- tags = {
            - Name        = "example-bucket"
            - Environment = var.environment
          - }
### meta-arguments
- In Resource Blocks
  - depends_on
  - count
    - count = 3
              - or
              - count = length(var.foo_bar)
    - var.foo_bar[count.index]
    - foo_bar = ["aaa", "bbb", "ccc"]
  - for_each
  - provider
  - lifecycle
- In Modules
  - depends_on
  - count
  - for_each
  - providers
### Loops
- Define map or set of strings
  - for_each
    - map
      - for_each = {
    - "Group1" = "jack.roper@madeup.com",
    - "Group2" = "bob@madeup.com",
    - "Group3" = "john@madeup.com"
## }
- Access object
  - each.key
  - each.value
### Conditionals
- condition ? true_val : false_val
### Functions
- Categories
  - String
    - format
    - join
    - split
    - flatten
    - slice
  - Numeric
    - min
    - max
    - pow
    - range
  - Collection
    - length
    - lookup
    - merge
    - concat
  - Date and Time
    - formatdate
    - timestamp
  - Filesystem
    - file
    - filexists
    - abspath
  - IP Network
    - cidrsubnet
    - cidrhost
  - Encoding
    - base64encode
    - base64decode
    - jsonencode
    - yamldecode
  - Type Conversion
    - tobool
    - tomap
    - tolist
### Operators
- Logical
  - X || Y
    - return true if either X or Y is true
  - X && Y
    - return true only if both X and Y are true
- Arithmetic
- Equality operators
- Comparison operator
### Dynamic Blocks
- main.tf
  - resource "azurerm_virtual_network" "dynamic_block" {
              - name                = "vnet-dynamicblock-example-centralus"
              - resource_group_name = azurerm_resource_group.dynamic_block.name
              - location            = azurerm_resource_group.dynamic_block.location
              - address_space       = ["10.10.0.0/16"]
              - dynamic "subnet" {
                - for_each = var.subnets
                - iterator = item   #optional
                - content {
                  - name           = item.value.name
                  - address_prefix = item.value.address_prefix
                - }
              - }
            - }
- variables.tf
  - variable "subnets" {
              - description = "list of values to assign to subnets"
              - type = list(object({
                - name           = string
                - address_prefix = string
              - }))
            - }
- terraform.tfvars
  - subnets = [
              - { name = "snet1", address_prefix = "10.10.1.0/24" },
              - { name = "snet2", address_prefix = "10.10.2.0/24" },
              - { name = "snet3", address_prefix = "10.10.3.0/24" },
              - { name = "snet4", address_prefix = "10.10.4.0/24" }
            - ]
### Handle credentials
- Mark sensitive variables
  - sensitive = true
- Use env variables
  - TF_VAR_foo_bar
  - becomes var.foo_bar
## Managing environments
### Environments on branches
- Significant code duplication
- Propagating changes is tricky and error prone
- Can isolate environments
- Navigating whats deployed is easier
### Environments in subdirectories
- Requires copy paste between directories
### Terraform Workspaces
- Separate state for each workspace
- Specify env specific .tfvars
- Seeing whats deployed is hard because not in code
- Not a suitable isolation for different credentials and access
### Terragrunt
- Uses directories to separate environments
- terragrunt.hcl files specify the different input values per env
- Can specify different backends using a root terragrunt.hcl file and a parametrised remote_state
- Modules can be versioned using git tags and setting terraform { source = github URL?refv1.x }
- Use dependency block to read an output variable from another module
- catalog command can browse module catalogue
- scaffold command can scaffold out files for configuring a module
  - Figures out module URL and latest tag
  - Creates a boilerplate file to use a module
  - Parses all module input variables and generates placeholders