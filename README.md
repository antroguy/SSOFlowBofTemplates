# SSO Flow BOF Templates

## Overview
These are **template** Beacon Object Files (BOFs) demonstrating how to use a current users context to access target applications based off the configured SSO authentication flows . They are designed to be easily modified for different applications, identity providers, and authentication flows. 

## Templates

### ADFS-GitLab.cpp
SAML 2.0 flow using ADFS with Kerberos authentication to access GitLab.

### PRT-Github.cpp
SAML 2.0 flow using Azure AD with Primary Refresh Token (PRT) to access GitHub Enterprise.

### PRT-Github-OIDC.cpp
OpenID Connect flow using Azure AD with Primary Refresh Token (PRT) to access GitHub Enterprise.

## Important Notes

⚠️ **These are templates, not ready-to-use BOFs.**

Before using these templates, you **must** modify configuration values for your environment:
- Hostnames and domains
- URL paths
- Token/cookie names
- Authentication endpoints

Each BOF has a `CONFIGURATION` section at the top with values that need to be changed.

## Using These Templates

These templates are meant to be:

1. **Starting points** for creating BOFs targeting applications protected behind SSO
2. **Easy to modify** for different IDPs and applications
3. **Great for AI assistance** - Use these as POCs when working with Claude Code or other AI tools to generate new variants for your specific targets. I typically just figure out the necessary requests using fiddler, and than provide those requests to Claude Code with this project, and it can easily generate the BOF you need. 

Each template includes detailed flow documentation in the source code explaining the complete authentication sequence.

## Workflow

1. Pick the template that matches your target's authentication protocol
2. Capture the real authentication flow in fiddler
3. Update configuration values in the BOF
4. Modify any application-specific logic as needed
5. Compile and test

Or simply share the template with Claude along with your target's authentication flow, and let it help you adapt the code.

## Disclaimer

For authorized security testing only.
