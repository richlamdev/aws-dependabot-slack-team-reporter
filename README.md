# AWS Dependabot Slack Team Reporter

## 🧩 Overview

This setup deploys a Lambda that performs the following tasks:

1. Utilizes a GitHub App for authentication
2. Reads repositories to parse `.github/CODEOWNERS`
    -in the absence of CODEOWNERS file, the `security team` becaomes the default
    (this is to have the security team track down and assign appropriate ownership)
3. Obtains a list of non-archived repositories
4. Fetches Dependabot alerts for each repository
5. Posts alerts to Slack channels based on team ownership

---

## 📦 Design

This architecture is templated for two lambda deployments that are nearly identical.  Why?

1. Allows for convenient deployment in the same AWS account, without conflicts of resource names
2. Enables deploying two lambdas for different GitHub organizations,

---

## 🚀 Deployment

### Prerequisites

- AWS CLI and [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- GitHub App credentials stored in **AWS Secrets Manager**
  Preferably all Github repositories have the ./github/CODEOWNERS file populated
- Slack Webhook URLs mapped to team names

***Note**: The GitHub App must have the `metadata: read`, `contents: read` and `dependabot: read` permission

### 1. Clone the repo

```
git clone https://github.com/richlamdev/aws-dependabot-slack-team-reporter.git
cd aws-dependabot-slack-team-reporter
```

### 2. Set environment variables

Set the following Parameter variable in the template file, or change it when prompted during guided deployment

- `GitHubOrg` – Your GitHub organization name

Set the following values in AWS Secrets manager:

- `GITHUB_APP_ID`   – GitHub App ID
- `GITHUB_APP_PEM`  – GitHub App PEM key
- `TEAM_TO_CHANNEL` – JSON map of team slugs to Slack webhook URLs

After setting the above values in AWS Secrets manager, replace the placeholder ARNs in the template.yaml file

Example `SLACK_TEAM_MAPPING`:

```json
{
  "frontend": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
  "backend": "https://hooks.slack.com/services/AAA/BBB/CCC",
  "security": "https://hooks.slack.com/services/DEF/GHI/JKL"
}
```
While it is possible to have the GITHUB_APP_ID and GITHUB_APP_SECRET_NAME in the same secret as a JSON blob,
it involves additional steps to format the PEM correctly for storage as well as parse the PEM key accordingly
during retrieval.  By keeping it a separate secret it's a straight forward copy and paste to store the key,
and likewise keeps the retrieval simple.

### 3. Deploy with AWS SAM

Authenticate to AWS via CLI.

Then execute the following commands:
```
sam build
sam deploy --guided
```

Follow the prompts to configure the deployment stack, region, and parameters.

Optionally, monitor the CloudFormation stack in the AWS Management Console.
When the stack is complete, you can find the Lambda function ARN in the Outputs section.

---

## 🛠️ Configuration

The Lambda uses the following AWS resources:

- **Secrets Manager** for storing GitHub App private key
- **EventBridge** cron for scheduling scans
- **Policies** with minimal required permissions
- **Tags** to indicate ownership and deployment or resources. (Who doesn't tag their resources? /sarcasm)

GitHub App must have these permissions:

- `metadata: read`
- `contents: read`
- `dependabot: read`

---

## 🧪 Testing

You can test the Lambda functions locally using the SAM CLI (docker desktop or docker engine must be running):

```
sam build && sam local invoke DependabotFunction
```

---

## 📁 Project Structure

```
.
│
├── deployments/
│   │
│   ├── production/
│   │    └── template.yaml            # Production account template
│   │
│   └── staging/
│        └── template.yaml            # Staging account template
│
└── src/
    ├── dependabot-slack-team.py      # Entrypoint for scheduled Lambda
    └── requirements.txt              # Python dependencies
```

---

## 👥 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss the proposal.

---

## 🛡 License

[MIT](LICENSE)

---

## 📬 Maintainer

Created by [@richlamdev](https://github.com/richlamdev)
