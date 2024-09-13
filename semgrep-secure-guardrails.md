# Semgrep Secure Guardrails
## Why: Security must scale
### Vulnerabilities are prevalent
### Problems in underlying code
### Security testing is often too slow
### Need to balance complexity with speed
- Fast, easy, dumb regex based linters
- Powerful, complex, slow, whole program static analysis
### Detect if code is secure for future use
### Requirements for developer tools
- Relevant to developers work
- Efficient in meeting the developer needs
- Useable and well integrated into workflow
## What: The secure and easy way
### Borrow ideas from DevOps movement
### Security as a shared responsibility with shared goals
- Ship features fast
- Prevent and fix vulnerabilities
- Security is not special - plan and scope with rest of work
### Secure by default
- Safe to use no matter the calling context
- Eliminate classes of bugs
  - secrets
    - time spent
      - bug bounty
      - rotating secrets
      - code review
      - threat model
    - e.g. paved road
      - AWS secrets manager
      - Library
        - Python
        - Java
  - SQLi
    - e.g. parameterised queries
  - XSS
    - e.g. Java Server Faces
  - CSRF
    - e.g. use Sec Fetch headers
### Secure guardrail
- Catch straying from the secure path
### Self service security
### Security Maturity Frameworks
- BSIMM
  - SSDL Touchpoints
    - Code Review
      - CR2.5 - Assign tool mentors
      - CR2.6 - Use automated tools with tailored rules
      - CR2.7 - Use a top N bugs list
- OWASP SAMM
  - Security Testing
    - Progressively customise the automated tests
    - Increase frequency of execution
    - Prioritise testing components based on their risk
### Customise rules
- increases developer interaction
- increases fix rate
## Semgrep Architecture
### Code
- Actual code from supported languages
### Rules
- Yaml patterns and metadata
### Concrete Syntax Trees (CST)
- tree-sitter parsers
### Abstract Syntax Trees (AST)
### Analysis
- Search mode
- Taint mode
- Join mode
- Extract mode
### Rule Writing Exercises
- (...) ellipsis operator
  - find 0 or more arguments/lines of code
- enforce ordering of function calls
### Rule tuning analogy
- Min vs Max
- Min
  - Find only real bugs
  - Expect there will be false negatives (bugs missed)
  - Suitable if dont have capacity to triage many findings
  - Some risk is ok
- Max
  - Try to catch all bugs
  - There will be false positives (incorrect markings)
  - Suitable if bugs are costly or unacceptable
## Who: Success stories
### Netflix
- Old way
  - in-house consulting
    - no long term relationships
    - no clear priorities
  - per app assessment does not scale
- New way
  - Provide context not control
    - Recommended, not required
  - Partnerships
    - Invest in paved road together
- Example - incomplete authentication
  - Wall-E
    - Build a unified frontend
    - Tech agnostic
    - DDoS Protection
    - SSO Provider
    - WAF
    - Logging Metrics and Tracing
- Lessons learned
  - Subtopic 1
## Advanced Semgrep
### Metavariable Operators
- Metavariable-regex
  - Zoom in on specified metavariable and check it for specific regex
- Metavariable-comparison
  - Compare specific integer evaluations
  - Evaluate if strings in other strings
- Focus-metavariable
  - Zoom in finding on specific metavariable
- Metavariable-type
  - Evaluate the type expression in the target language
- Metavariable-analysis
  - Entropy analyser can help to determine secrets
### pattern-inside
- Combine with pattern to zoom in
### Fix
- Suggested autofix
- Can re-use metavariables
- How to fix with dynamic number of variables
  - Metavariable ellipsis
    - ($...ARG)
### Taint mode
- Taint source
  - Examples of user input
    - URL parameters
    - Cookies
    - data from 3rd party service
- Taint sink
  - Examples of where untrusted data used
    - Unparameterized SQL query
    - shell exec()
- Propagator
  - Where input propagates
    - eg string concatentation
- Sanitizers
  - Where input is sanitized
- Semgrep operators
  - mode: taint
  - pattern-sources
  - pattern-sinks
  - pattern-sanitizers
  - pattern-propagators
    - pattern
    - from
    - to
  - options
    - taint_assume_safe_numbers: true
    - taint_assume_safe_booleans: true
    - taint_assume_safe_functions: true
## How: Think long term and high impact
### Select vulnerabilitity class
- Focus on best ROI
- Reduce risk and ensure a baseline
- Eliminate bug classes
### Build a scalable solution and make it default
- Detect lack of secure default
- Find bug (automated)
- Find bug (manual)
- Write PoC Exploit
### Measure adoption
- Track costs and fix time
- Track adoption of secure defaults
- Gamify and use friendly peer pressure
### Drive organic adoption
- Integrate security into existing features
- Add non security features
- Use guardrails to check, observe and enforce adoption
- Track Effective False Positive rate
  - Any marking a developer wont fix
- Track False Positive rate
  - Any secure code marked as insecure
- Use better tools
  - Relevant
  - Efficient
  - Well integrated
  - Useable
  - Enables customisation
## Semgrep Assistant (AI)
### Autofix
- suggested commits
### Memories
- give organisational specific context to how to fix i.e. recommended library
### Contextualisation
- Identify code types and tag
  - i.e. AuthN, Payments, Infra etc
### Visibility into backlog
- Trends of
  - New
  - Fixed
  - Ignored