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

### Required Access
- AWS Academy Learner Lab or sandbox AWS account that allows provisioning KMS, S3, DynamoDB, Lambda, EventBridge, and VPC endpoints.
- Permission to assume the lab IAM role (`LabRole` by default) and validate identity with `aws sts get-caller-identity`.
- Network reachability from AWS CloudShell or a workstation to AWS service endpoints in `us-east-1` or `us-west-2`.

### Required Tools
- **AWS CLI** v2.x (validated by `aws --version`; older releases are blocked by the scripts).
- **bash** 4.x or later (GNU or compatible shell).
- **python3** (invoked by helper snippets inside the shell scripts).
- **zip** utility for Lambda packaging.
- Optional: `script`, `tee`, or similar tooling to capture CLI transcripts for submission.

`jq` is not required; evaluation logic uses Python for JSON parsing.

### Required Knowledge
- Familiarity with IAM, KMS key policies, and encryption requirements.
- Experience hardening S3, DynamoDB, and Lambda workloads.
- Understanding of VPC interface/gateway endpoints and private API Gateway access.
- Comfort with AWS CLI troubleshooting, CloudWatch Logs, and event-driven architectures.

## 🚀 Quick Start

### For Competitors (Challenge Takers)

1. **Prepare your CloudShell workspace**
   ```bash
   sudo mkdir -p /workspace
   sudo chown cloudshell-user:cloudshell-user /workspace
   cd /workspace
   ```
   Run `aws sts get-caller-identity` once to confirm you are assuming the Learner Lab role.

2. **Clone the lab repository**
   ```bash
   git clone https://github.com/ethnus/CTF_MockTest_03.git
   cd CTF_MockTest_03/scripts
   ```

3. **Deploy the broken environment**
   ```bash
   bash init.sh
   ```
   Optional overrides: export `AWS_REGION`, `STATE_FILE`, or `LAB_ROLE_NAME` before running for custom regions, state paths, or IAM role names.

   **Quick one-liner (CloudShell ready):**
   ```bash
   sudo mkdir -p /workspace && sudo chown cloudshell-user:cloudshell-user /workspace && cd /workspace && git clone https://github.com/ethnus/CTF_MockTest_03.git && cd CTF_MockTest_03/scripts && bash init.sh && bash eval.sh
   ```

4. **Run the initial evaluation**
   ```bash
   # Learner mode (terse, colorized table)
   bash eval.sh
   # Instructor mode (adds diagnostics; still generic tasks)
   bash eval.sh --verbose
   ```
   The evaluator shows a colorized tabular scorecard with generic tasks and opaque statuses, e.g.:
   
   +----+-----------+---------------+
   | #  | Task      | Status        |
   +----+-----------+---------------+
   | 1  | Task 1    | NOT ACCEPTED  |
   | 2  | Task 2    | ACCEPTED      |
   | .. | ...       | ...           |
   +----+-----------+---------------+
   Accepted: N/10
   
   Color control: add `--color` or `--no-color` if your terminal needs it.
   
   It does not reveal check details. Instructors may pass `--verbose` (or set `EVAL_VERBOSE=1`) to add per-task diagnostic logs; labels remain generic.

5. **Capture plans and artifacts**
   - Store CLI transcripts, `eval` output, and remediation notes under `../state/` so they remain outside version control.
   - Example: `mkdir -p ../state/artifacts && bash eval.sh | tee ../state/artifacts/eval-$(date +%Y%m%d%H%M).log`
   - Keep the generated `state/serverless-lab-state.json` safe; it records all resource identifiers for the session.

6. **Troubleshoot and remediate**
   - Investigate with AWS Console and CLI (KMS, S3, DynamoDB, Lambda, EventBridge, VPC endpoints).
   - Apply one fix at a time; re-run `bash eval.sh` after each change to confirm progress.
   - Use `bash remediate.sh --debug` for high-verbosity tracing: prints each AWS command, exit code, elapsed time, and truncated stdout/stderr, plus a plan and state overview to aid diagnosis.

7. **Finish the challenge**
   - When all ten checks read `ACCEPTED`, the evaluator prints `FLAG{...}`. Capture the flag and document the remediation steps you used.
8. **Clean up when finished**
   - Run `bash teardown.sh` (add `--keep-state` if you want to archive the state file) to remove the lab resources once your session is complete.
9. **State accidentally removed?**
   - Scripts automatically look for a backup at `~/.lab-state/serverless-resiliency-lab/<ACCOUNT>-<REGION>/serverless-lab-state.json` and restore it when possible.
   - If neither the working copy nor the backup exists but resources remain, run `bash rebuild-state.sh` to regenerate the manifest before invoking `bash remediate.sh` or `bash eval.sh`.
10. **Role alignment (Learner Lab)**
   - If your assumed role isn’t `LabRole`, set `LabRoleName` to your active role so KMS policy checks line up:
     ```bash
     export LAB_ROLE_NAME="$(aws sts get-caller-identity --query Arn --output text | awk -F/ '/assumed-role/ {print $2}')"
     export LabRoleName="$LAB_ROLE_NAME"
     ```
     Both `remediate.sh` and `eval.sh` honor `LAB_ROLE_NAME` and prefer it over the value in the state file.

### For Instructors (Challenge Administrators)

1. **Provision the environment**
   ```bash
   cd CTF_MockTest_03/scripts
   bash init.sh
   ```
2. **Validate the baseline**
   ```bash
  bash eval.sh --verbose
   ```
   Ensure all controls show `NOT ACCEPTED` before handing access to competitors.
3. **Support the cohort**
   - Share guardrails or hints aligned with the ten controls.
   - Demonstrate fixes live by applying remediations and re-running `bash eval.sh` for proof.
  - Use `bash remediate.sh` as a reference solution (do not distribute to competitors).
  - To reset a learner environment back to broken state without redeploying, run: `bash init.sh --reinit` (uses the state manifest).
   - Encourage competitors to keep plan files, remediation notes, and evaluation logs under `state/` (e.g., `state/artifacts/`) for consistent evidence capture.
4. **Cleanup guidance**
   - When the cohort wraps, run `bash teardown.sh` to remove deployed resources. Use `bash teardown.sh --keep-state` if you need to retain the manifest for grading or evidence.
   - If a learner deletes the state manifest mid-session, regenerate it with `bash rebuild-state.sh` prior to providing remediation assistance.

## 🧭 Environment Variables
- `STATE_FILE` – Path for deployment metadata (default `state/serverless-lab-state.json`).
- `AWS_REGION` or `AWS_DEFAULT_REGION` – Target region (`us-east-1` or `us-west-2` allowed).
- `LAB_ROLE_NAME` – IAM role assumed by the evaluation checks (default `LabRole`).
- `VERBOSE` – Controls high-level logs in `init.sh` and `remediate.sh` (default `1`).
- `DEBUG` – Command-level tracing in `remediate.sh` (default `1`; pass `--debug` explicitly or set `DEBUG=0` to reduce noise).
- `DEBUG_MAX_BYTES` – Max bytes of stdout/stderr echoed per AWS CLI call in debug mode (default `4096`).
- `EVAL_VERBOSE` – Set to `1` for a more chatty evaluator; default `0` for learners.
- `FORCE_COLOR` / `NO_COLOR` – Force-enable or disable ANSI colors in `eval.sh` output.

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
| `scripts/remediate.sh` | Instructor reference solution (do not share with competitors) | Idempotent; includes verification with retries to account for AWS propagation |
| `scripts/teardown.sh` | Destroys lab resources recorded in the state manifest | Accepts `--keep-state` to retain the manifest after cleanup |
| `scripts/rebuild-state.sh` | Reconstructs `state/serverless-lab-state.json` when resources exist but the manifest is missing | Run from `scripts/` with AWS CLI v2 credentials |

## 🌐 Recommended Environment Setup (AWS CloudShell)

```bash
sudo mkdir -p /workspace
sudo chown cloudshell-user:cloudshell-user /workspace
cd /workspace
git clone https://github.com/ethnus/CTF_MockTest_03.git
cd CTF_MockTest_03/scripts
bash init.sh
bash eval.sh
# ...when you're finished with the lab
# bash teardown.sh
```

CloudShell home directories are 1 GB; `/workspace` offers more headroom for artifacts and zip builds.

## 🔧 Troubleshooting Guide

- **`init.sh` aborts due to existing state**: Remove `state/serverless-lab-state.json` (or change `STATE_FILE`) only after manually cleaning AWS resources.
- **`aws` command not found or wrong version**: Install AWS CLI v2 (check `aws --version` for `aws-cli/2.x`).
- **Evaluation still failing after a fix**: Re-run `bash eval.sh` (or `bash eval.sh --verbose` for diagnostics). Use targeted AWS CLI `describe` calls to inspect current resource configuration.
- **Permission errors when modifying resources**: Confirm you are assuming the lab role (`LabRole` by default) and that the Learner Lab session is active.
- **Lambda packaging issues**: The bootstrap script bundles the function automatically; you do not need to re-upload unless you modified the code.
- **Cleaning up**: Run `bash teardown.sh` after validating the challenge to remove deployed resources (add `--keep-state` if you need the manifest).

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
