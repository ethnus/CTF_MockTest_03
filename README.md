# Ethnus AWS Mock Test Project – Serverless Resiliency Lab

[![AWS](https://img.shields.io/badge/AWS-Cloud-orange)](https://aws.amazon.com/)
[![Serverless](https://img.shields.io/badge/Pattern-Serverless-blue)](https://aws.amazon.com/serverless/)
[![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red)](https://github.com)

Hands-on AWS challenge for diagnosing and remediating misconfigured serverless workloads. Competitors stand up an intentionally broken deployment that mixes Lambda, API Gateway, DynamoDB, EventBridge, and VPC endpoints, then restore operational and security baselines to capture the final flag.

## 🎯 Challenge Overview

This **Capture The Flag (CTF)** scenario focuses on serverless resilience, compliance, and connectivity. You will bootstrap a lab environment that includes multiple defects across infrastructure, security, and application layers. Resolving all issues triggers the evaluation script to emit a deterministic flag.

### What Gets Deployed
- **AWS KMS CMK** with an overly restrictive key policy
- **S3 bucket** that lacks encryption and mandatory governance tags
- **DynamoDB table** with default encryption and point-in-time recovery disabled
- **Lambda function** packaged locally with misconfigured environment variables
- **EventBridge rule** wired to the Lambda but left disabled
- **REST API (API Gateway)** restricted to a non-existent VPC endpoint
- **VPC, Subnet, Security Group** for Lambda execution
- **S3 Gateway endpoint** missing route table attachments
- **Execute-API Interface endpoint** for private API Gateway access

The deployment is tailored for AWS Academy Learner Lab permissions and executes entirely via the provided bash scripts.

### The 10 Challenges Checked by `eval.sh`
After installation you will see ten failing controls. Each must be remediated in AWS:

1. **Key access: lab role permissions** – Update the CMK policy so the lab IAM role can encrypt/decrypt.
2. **Data-at-rest: bucket encryption** – Enforce default KMS encryption on the telemetry bucket.
3. **Resource governance: tagging** – Apply required `Project` and `CostCenter` tags to the bucket.
4. **DynamoDB encryption: KMS key** – Reconfigure table encryption to use the lab CMK.
5. **DynamoDB backups: PITR** – Enable continuous backups for the telemetry table.
6. **Private data path: DynamoDB VPC endpoint** – Add a Gateway endpoint for DynamoDB in the VPC.
7. **S3 routing: endpoint associations** – Attach the S3 Gateway endpoint to the route table.
8. **Lambda configuration: environment variables** – Fix the table name typo in the Lambda configuration.
9. **Event processing: heartbeat rule** – Re-enable the disabled EventBridge schedule.
10. **API access: VPC endpoint policy** – Align the API policy with the actual execute-api endpoint ID.

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────┐
│                    AWS Account                        │
├───────────────────────────────────────────────────────┤
│  KMS CMK (alias/serverless-resiliency-lab)            │
│  S3 Bucket (telemetry storage)                        │
│  DynamoDB Table (pk/sk items)                         │
│                                                       │
│  VPC 10.20.0.0/24                                     │
│   ├─ Private Subnet 10.20.0.0/28                      │
│   │   ├─ Lambda Function (VPC-enabled)                │
│   │   ├─ Security Group (egress-only default)         │
│   │   └─ VPC Endpoints                                │
│   │       ├─ S3 Gateway Endpoint (detached routes)    │
│   │       └─ Execute API Interface Endpoint           │
│   │                                                   │
│   └─ Route Table                                      │
│                                                       │
│  API Gateway (PRIVATE, /ingest) → Lambda proxy        │
│  EventBridge Rule (rate/10m) → Lambda target          │
└───────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

### Access Requirements
- AWS Academy Learner Lab or sandbox AWS account with IAM role capable of creating the above resources.
- Sufficient service quotas for KMS keys, DynamoDB tables, Lambda functions, API Gateway REST APIs, and VPC endpoints in `us-east-1` or `us-west-2`.

### Local Tooling
- **AWS CLI** v2.0 or later (credentialed for the target account)
- **bash** (GNU or compatible)
- **python3** (needed for inline evaluation helpers)
- **zip** command (used to package the Lambda function)

`jq` is not required; all JSON parsing is handled in Python.

### Baseline Knowledge
- Familiarity with IAM and KMS key policies
- Experience securing S3, DynamoDB, and Lambda workloads
- Understanding of VPC endpoints and private API Gateway access
- Comfort with AWS CLI troubleshooting and CloudWatch logs

## 🚀 Quick Start

### Competitors
1. **Clone the workspace**
   ```bash
   git clone https://github.com/ethnus/serverless-resiliency-lab.git
   cd serverless-resiliency-lab/scripts
   ```
2. **Run the bootstrap**
   ```bash
   bash init.sh
   ```
   Use `STATE_FILE` or `AWS_REGION` if you need non-default paths or regions.
3. **Check the initial scorecard**
   ```bash
   bash eval.sh
   ```
   Expect all ten controls to report `INCOMPLETE`.
4. **Remediate in AWS**
   - Apply fixes through the AWS Console or CLI.
   - Re-run `bash eval.sh` after each change to monitor progress.
5. **Capture the flag**
   - Once all checks pass the script prints `FLAG{...}`. Record this for submission.

### Instructors / Proctors
1. Provision the environment with `bash init.sh`.
2. Use `bash eval.sh` to verify the expected failure state before handing the account to participants.
3. Optionally pre-create hints or guardrails for each control (see Challenge Breakdown).
4. To demonstrate solutions, apply the fixes manually or through automations, then run `bash eval.sh` to confirm the clean state.
5. Clean up resources manually (no teardown script is provided). Remove the API, Lambda, VPC endpoints, DynamoDB table, bucket, and CMK before ending the Learner Lab session.

## 🧭 Environment Variables
- `STATE_FILE` – Path for deployment metadata (default `state/serverless-lab-state.json`).
- `AWS_REGION` or `AWS_DEFAULT_REGION` – Target region (`us-east-1` or `us-west-2` allowed).
- `LAB_ROLE_NAME` – IAM role assumed by the evaluation checks (default `LabRole`).

These may be set prior to running `init.sh` and are read by `eval.sh`.

## 📊 Challenge Breakdown

| # | Control | Issue Triggered by `init.sh` | Expected Remediation |
|---|---------|------------------------------|----------------------|
| 1 | KMS Policy | Key policy only trusts the root account | Grant the lab IAM role encrypt/decrypt permissions |
| 2 | S3 Encryption | Bucket created without default encryption | Enable SSE-KMS using the lab CMK |
| 3 | S3 Tagging | Governance tags not applied | Add `Project=ServerlessLab` and `CostCenter=Training` |
| 4 | DynamoDB SSE | Table uses AWS-owned encryption | Reconfigure to use the lab CMK |
| 5 | DynamoDB PITR | Point-in-time recovery disabled | Enable continuous backups |
| 6 | DynamoDB Endpoint | No Gateway endpoint for DynamoDB | Create endpoint and associate with the VPC |
| 7 | S3 Endpoint Routes | S3 endpoint detached from route table | Attach route table to the S3 endpoint |
| 8 | Lambda Env | Typo in `DDB_TABLE_NAME` variable | Update Lambda environment to the actual table name |
| 9 | Event Rule | Scheduler left `DISABLED` | Enable the rule so it triggers heartbeat invocations |
|10 | API Policy | Policy restricts to fake VPC endpoint ID | Replace with the real execute-api VPC endpoint ID |

## 🛠️ Available Scripts

| Script | Purpose | Notes |
|--------|---------|-------|
| `scripts/init.sh` | Deploys the lab infrastructure with faults | Stops if state exists to avoid clobbering |
| `scripts/eval.sh` | Runs remediation checks and prints the flag on success | Requires AWS CLI v2+, reads `STATE_FILE` |
| `scripts/remediate.sh` | Instructor reference solution (do not share with competitors) | Not executed automatically |
| `scripts/report.sh` | Augments evaluation with result logging for cohort tracking | Optional, requires writable `state/` |

## 🌐 Recommended Environment Setup (AWS CloudShell)

```bash
sudo mkdir -p /workspace
sudo chown cloudshell-user:cloudshell-user /workspace
cd /workspace
git clone https://github.com/ethnus/serverless-resiliency-lab.git
cd serverless-resiliency-lab/scripts
bash init.sh
bash eval.sh
```

CloudShell home directories are 1 GB; `/workspace` offers more headroom for artifacts and zip builds.

## 🔧 Troubleshooting Guide

- **`init.sh` aborts due to existing state**: Remove `state/serverless-lab-state.json` (or change `STATE_FILE`) only after manually cleaning AWS resources.
- **`aws` command not found or wrong version**: Install AWS CLI v2 and ensure `aws --version` reports `2.x`.
- **Evaluation still failing after a fix**: Re-run `bash eval.sh` to refresh cache. Use `aws` CLI commands echoed in the script to inspect current resource configuration.
- **Permission errors when modifying resources**: Confirm you are assuming the lab role (`LabRole` by default) and that the Learner Lab session is active.
- **Lambda packaging issues**: The bootstrap script bundles the function automatically; you do not need to re-upload unless you modified the code.
- **Cleaning up**: There is no `teardown.sh`. Delete the API Gateway deployment, Lambda, DynamoDB table, bucket (after emptying), VPC endpoints, security group, subnet, VPC, and KMS key manually before closing the lab.

## 🏆 Success Criteria

- `bash eval.sh` reports zero failures and prints `FLAG{<sha256-prefix>}` using `AccountId:Region:ApiId`.
- Lambda invocations write items to DynamoDB and objects to S3 without permission errors.
- API Gateway `/ingest` endpoint (private) can invoke the Lambda through the VPC endpoint.
- EventBridge rule triggers the Lambda successfully on the 10-minute schedule.

## 🎓 Learning Outcomes

- Hardening serverless workloads with IAM and KMS
- Meeting tagging and data protection mandates across S3 and DynamoDB
- Configuring private access paths with VPC endpoints and API Gateway policies
- Diagnosing Lambda environment and networking issues in VPC-enabled functions
- Operating event-driven architectures with EventBridge schedules

Good luck, and have fun restoring resiliency to the serverless stack! 🚀

