# Project Title

Enforce authentication to AWS account via CLI with MFA token usage

## Quick summary
It's a best practice to protect your account and its resources by using a multi-factor authentication device (MFA). 
If you plan to interact with Company resources using the AWS Command Line Interface (CLI) you must use MFA device and request each time a temporary session token instead.

## Briefly
This script prompts you to select target profile from your locally stored AWS config profiles and ask to provide MFA token for this profile. 
If successful new AWS temporary credentials will be stored in your AWS CLI configuration and credentials files.

NOTE. New profiles name will be generated with mask 'mfa-<old_profile_name>'

## Getting Started

### Prerequisites

Please see REQUIREMENTS.TXT

```
pip install -r requirements.txt
```

### Installing

Clone repository to you local folder.

### Configuration

1. Create IAM policy (see template in additional/iam_mfa_policy.template)
2. Create IAM group, move all users to this group and assign newly created IAM policy to this group.
3. Add alias to your shell run command file (.bashrc, .zshrc, etc)

```
alias awslogin='python ~/<PATH_TO_REPo>/aws-cli-auth-with-mfa/awsmfalogin.py'
```
## Usage
Run script and provide profiles ids just simply typing integer or integers separated by any symbol or type 'all'.


## References
https://aws.amazon.com/premiumsupport/knowledge-center/authenticate-mfa-cli/


## Authors

* **Nikolay Srebniuk**

