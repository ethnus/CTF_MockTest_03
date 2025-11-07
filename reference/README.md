# Ethnus AWS Mock Test Project

[![AWS](https://img.shields.io/badge/AWS-Cloud-orange)](https://aws.amazon.com/)
[![Terraform](https://img.shields.io/badge/Terraform-Infrastructure-blue)](https://terraform.io/)
[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow)](https://github.com)

A comprehensive AWS serverless architecture challenge designed to test cloud engineering skills in a CTF (Capture The Flag)-type environment.

## 🎯 Challenge Overview

This is a **Capture The Flag (CTF)** challenge focused on AWS cloud security and infrastructure troubleshooting. Competitors will deploy a deliberately misconfigured serverless architecture and must identify and fix **12 specific issues** to complete all challenges.

### What Gets Deployed
- **S3 Bucket** with KMS encryption (missing organizational standards)
- **DynamoDB Table** for order storage (governance compliance issues)  
- **Lambda Functions** for data processing (performance & configuration issues)
- **VPC Infrastructure** with private networking (routing & security issues)
- **API Gateway** for private API access (integration & policy issues)
- **SNS Topic** for notifications (communication restrictions)
- **EventBridge Rule** for scheduling (automation disabled)
- **KMS Key** for encryption

### The 12 Challenges
After deployment, the evaluation will show **12 INCOMPLETE** challenges:

1. **Resource governance: storage** - Review organizational standards for cloud resources
2. **Resource governance: database** - Ensure compliance with governance policies
3. **Performance optimization: compute** - Review and optimize resource allocation
4. **Application configuration: runtime** - Align runtime parameters with requirements
5. **Communication services: publish** - Enable proper message delivery mechanisms
6. **Network security: data access** - Configure appropriate access permissions
7. **Network routing: service access** - Optimize traffic routing for cloud services
8. **API service: backend integration** - Establish proper service connections
9. **API security: access restrictions** - Implement and enforce access policies
10. **Process automation: scheduling** - Activate automation workflows
11. **System integration: end-to-end** - Ensure all service dependencies are operational
12. **Service delivery: final verification** - Complete mission requirements

This challenge simulates a real-world AWS environment where you'll need to implement, secure, and troubleshoot a serverless architecture while working within the constraints of AWS Academy Learner Lab.

## 🏗️ Architecture

The project implements a multi-VPC serverless architecture with the following components:

```
┌─────────────────┐    ┌──────────────────────────────┐
│   VPC A (App)   │    │      Other AWS Services      │
│                 │    │                              │
│  ┌─────────────┐│    │ ┌─────────┐ ┌──────────────┐ │
│  │ API Gateway ││────│ │   S3    │ │  DynamoDB    │ │
│  │ (Private)   ││    │ │ (KMS)   │ │  (KMS)       │ │
│  └─────────────┘│    │ └─────────┘ └──────────────┘ │
│                 │    │                              │
│  ┌─────────────┐│    │ ┌─────────┐ ┌──────────────┐ │
│  │   Lambda    ││────│ │   SNS   │ │ EventBridge  │ │
│  │   Reader    ││    │ │ Topic   │ │    Rule      │ │
│  └─────────────┘│    │ └─────────┘ └──────────────┘ │
│                 │    │                              │
│  ┌─────────────┐│    │ ┌─────────┐                  │
│  │   Lambda    ││────│ │   KMS   │                  │
│  │   Writer    ││    │ │   Key   │                  │
│  └─────────────┘│    │ └─────────┘                  │
└─────────────────┘    └──────────────────────────────┘
         │
    VPC Peering
         │
┌─────────────────┐
│   VPC B (Peer)  │
│                 │
│ Other Internal  │
│    Systems      │
└─────────────────┘
```

## 📋 Prerequisites

### Required Access
- **AWS Academy Learner Lab** account with active session
- Access to AWS CLI (configured with Learner Lab credentials)
- Basic understanding of AWS services

### Required Tools
- **Terraform** >= 1.5.0 (auto-installed by deploy script)
- **AWS CLI** >= 2.0
- **jq** (for evaluation script)
- **bash** (for running scripts)

### Required Knowledge
- AWS fundamentals (VPC, Lambda, S3, DynamoDB, IAM)
- Basic Terraform concepts
- JSON/YAML configuration
- Command line proficiency

## 🚀 Quick Start

### For Competitors (Challenge Takers)

1. **Setup Workspace (AWS CloudShell)**
   ```bash
   # Create workspace directory with sufficient storage
   sudo mkdir -p /workspace
   sudo chown cloudshell-user:cloudshell-user /workspace
   cd /workspace
   ```

2. **Clone Repository and Navigate**
   ```bash
   # Clone the challenge repository
   git clone https://github.com/ethnus/CTF_MockTest_01.git
   cd CTF_MockTest_01/scripts/
   ```

3. **Deploy Infrastructure**
   ```bash
   # Set your preferences (optional)
   export PREFIX="ethnus-mocktest-01"
   export REGION="us-east-1"
   
   # Deploy the challenge environment
   bash deploy.sh
   ```

   **Quick One-Liner:**
   ```bash
   sudo mkdir -p /workspace && sudo chown cloudshell-user:cloudshell-user /workspace && cd /workspace && git clone https://github.com/ethnus/CTF_MockTest_01.git && cd CTF_MockTest_01/scripts/ && bash deploy.sh && bash eval.sh
   ```

4. **Run Initial Evaluation**
   ```bash
   bash eval.sh
   ```
   You should see multiple `INCOMPLETE` status items - these are your challenges!

5. **Start Troubleshooting**
   - Use AWS Console, CLI, and documentation
   - Fix configurations one by one
   - Re-run `bash eval.sh` to check progress

6. **Complete the Challenge**
   - All 12 checks should show `ACCEPTED`
   - The final flag will be revealed

### For Instructors (Challenge Administrators)

1. **Setup and Deploy Competitor Environment**
   ```bash
   # Setup workspace directory (AWS CloudShell)
   sudo mkdir -p /workspace
   sudo chown cloudshell-user:cloudshell-user /workspace
   cd /workspace
   
   # Clone the challenge repository
   git clone https://github.com/ethnus/CTF_MockTest_01.git
   cd CTF_MockTest_01/scripts/
   
   # Deploy the infrastructure
   bash deploy.sh
   ```

2. **Verify Challenge State**
   ```bash
   bash eval.sh
   # Should show intentional misconfigurations
   ```

3. **Monitor Competitor Progress**
   Competitors can run `eval.sh` anytime to check their progress

4. **Provide Hints** (if needed)
   Each challenge has specific learning objectives (see Challenge Details below)

5. **Reset Environment** (if needed)
   ```bash
   # Fix all issues for demonstration
   bash remediate.sh
   
   # Completely clean up
   bash teardown.sh
   ```

## 📊 Challenge Structure

The evaluation script tests **12 key areas** of cloud architecture and security:

| # | Challenge | Focus Area | Learning Objective |
|---|-----------|------------|-------------------|
| 1 | Resource governance: storage | Compliance | Organizational tagging standards |
| 2 | Resource governance: database | Compliance | Resource labeling best practices |
| 3 | Performance optimization: compute | Performance | Resource limit optimization |
| 4 | Application configuration: runtime | Configuration | Environment parameter alignment |
| 5 | Communication services: publish | Messaging | Service access permissions |
| 6 | Network security: data access | Security | VPC endpoint policy configuration |
| 7 | Network routing: service access | Networking | Route table optimization |
| 8 | API service: backend integration | Integration | Service-to-service connectivity |
| 9 | API security: access restrictions | Security | Private API access control |
| 10 | Process automation: scheduling | Automation | Event-driven architecture |
| 11 | System integration: end-to-end | Testing | Multi-service dependencies |
| 12 | Service delivery: final verification | Completion | Full system functionality |

## 🛠️ Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `deploy.sh` | Deploy challenge infrastructure | `bash deploy.sh` |
| `eval.sh` | Evaluate current state (12 checks) | `bash eval.sh` |
| `remediate.sh` | Fix all issues (instructor use) | `bash remediate.sh` |
| `teardown.sh` | Complete cleanup | `bash teardown.sh` |

## 🌐 Environment Setup

### AWS Environment Requirements
```bash
# Verify AWS CLI access (usually automatic in Learner Lab)
aws sts get-caller-identity

# IMPORTANT: AWS CloudShell Setup (Recommended)
# Create workspace directory with more storage (home ~ is only 1GB)
sudo mkdir -p /workspace
sudo chown cloudshell-user:cloudshell-user /workspace
cd /workspace

# Install jq if not available (required for eval.sh)
sudo yum install jq -y  # For Amazon Linux/CloudShell
# OR: sudo apt-get update && sudo apt-get install jq -y  # For Ubuntu
```

### Supported Environments
- **AWS CloudShell** (Recommended)
- **EC2 instances** with appropriate IAM roles
- **Local environment** with AWS CLI configured
- **WSL on Windows** with AWS CLI

### Complete Setup Example
```bash
# Complete setup from scratch in AWS CloudShell
sudo mkdir -p /workspace
sudo chown cloudshell-user:cloudshell-user /workspace
cd /workspace

git clone https://github.com/ethnus/CTF_MockTest_01.git
cd CTF_MockTest_01/scripts/
bash deploy.sh
bash eval.sh
```

## 🔧 Troubleshooting Guide

### Common Issues

**"No space left on device" or storage issues in AWS CloudShell**
```bash
# AWS CloudShell home directory (~) is limited to 1GB
# Use /workspace directory instead (has more storage)
sudo mkdir -p /workspace
sudo chown cloudshell-user:cloudshell-user /workspace
cd /workspace
# Then clone and run from here
```

**"terraform not found"**
```bash
# The deploy script auto-installs terraform
bash deploy.sh
```

**"AWS credentials not configured"**
```bash
# Configure AWS CLI with your Learner Lab credentials
aws configure
# Or use environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_SESSION_TOKEN="your-token"
```

**"jq command not found"**
```bash
# Install jq for your system
# Ubuntu/Debian:
sudo apt-get install jq
# macOS:
brew install jq
# Windows: Download from https://jqlang.github.io/jq/
```

**Evaluation shows errors**
- This is expected! The infrastructure is intentionally misconfigured
- Use AWS Console and CLI to investigate issues
- Fix one problem at a time
- Re-run `eval.sh` to track progress

### Investigation Tips

1. **Use AWS Console**
   - Check Lambda function configurations
   - Review VPC endpoint settings
   - Examine API Gateway setup
   - Verify resource tags

2. **Use AWS CLI**
   ```bash
   # Check Lambda function details
   aws lambda get-function --function-name ethnus-mocktest-01-writer
   
   # List VPC endpoints
   aws ec2 describe-vpc-endpoints
   
   # Check DynamoDB table
   aws dynamodb describe-table --table-name ethnus-mocktest-01-orders
   ```

3. **Read Error Messages**
   - The eval script provides specific error context
   - Look for patterns in failed checks
   - Use AWS documentation for reference

## 🎓 Learning Objectives

Upon completion, you will demonstrate proficiency in:

- **AWS Well-Architected Framework** principles
- **Serverless architecture** design and implementation  
- **VPC networking** and security controls
- **Encryption and key management** with KMS
- **Infrastructure as Code** with Terraform
- **Security best practices** and compliance
- **Troubleshooting methodologies** for cloud systems
- **API Gateway** and Lambda integrations
- **Resource tagging** and governance

## 💡 Best Practices Reinforced

- **Least Privilege Access** - Restrict IAM and resource policies
- **Defense in Depth** - Multiple security layers
- **Encryption Everywhere** - Data at rest and in transit
- **Resource Tagging** - Consistent labeling for governance
- **Infrastructure as Code** - Versioned, repeatable deployments
- **Monitoring and Logging** - Observability throughout
- **Cost Optimization** - Efficient resource utilization

---

<details>
<summary><strong>🚨 SPOILER ALERT - Challenge Details & Solutions</strong></summary>

> **⚠️ WARNING**: The following section contains detailed challenge descriptions and solution hints. Only expand if you're an instructor or have completed the challenge!

### Summary Table of Fixes

| # | Challenge | Issue | Solution | AWS Service |
|---|-----------|-------|----------|-------------|
| 1 | Resource governance: storage | S3 Bucket is missing the required `CostCenter` tag. | Add tag `CostCenter=Ethnus` to the S3 bucket. | S3 |
| 2 | Resource governance: database | DynamoDB Table is missing the required `CostCenter` tag. | Add tag `CostCenter=Ethnus` to the DynamoDB table. | DynamoDB |
| 3 | Performance optimization: compute | `writer` Lambda function memory is too low (128MB). | Increase memory size to 256MB in the function's configuration. | Lambda |
| 4 | Application configuration: runtime | `reader` Lambda function has an incorrect DynamoDB table name in its environment variables. | Update the `DYNAMODB_TABLE` environment variable to the correct table name. | Lambda |
| 5 | Communication services: publish | `writer` Lambda IAM role lacks permission to publish to the SNS topic. | Add an inline policy to the IAM role granting `sns:Publish` permission on the topic. | IAM, SNS |
| 6 | Network security: data access | The VPC Endpoint for DynamoDB has a policy that is too restrictive. | Modify the endpoint policy to allow `dynamodb:PutItem` and `dynamodb:GetItem` actions for the Lambda roles. | VPC |
| 7 | Network routing: service access | The private subnet's route table is missing a route to the S3 VPC endpoint. | Add a route for the S3 prefix list ID to the S3 VPC endpoint in the route table. | VPC |
| 8 | API service: backend integration | The API Gateway integration for the `reader` Lambda is missing invocation permissions. | Add a resource-based policy to the `reader` Lambda granting `lambda:InvokeFunction` permission to API Gateway. | API Gateway, Lambda |
| 9 | API security: access restrictions | The private API Gateway is missing a resource policy to allow access from the VPC. | Add a resource policy to the API Gateway allowing `execute-api:Invoke` from the VPC Endpoint for Execute API. | API Gateway |
| 10 | Process automation: scheduling | The EventBridge (CloudWatch Events) rule that triggers the `writer` Lambda is disabled. | Enable the EventBridge rule. | EventBridge |
| 11 | System integration: end-to-end | Meta-challenge: `reader` function cannot read what `writer` writes. | This resolves automatically after fixing underlying issues (mainly #3, #4, #5, #6, #7, #10). | Multiple |
| 12 | Service delivery: final verification | Meta-challenge: The full end-to-end flow via API Gateway is not functional. | This resolves automatically after fixing API and integration issues (mainly #8, #9, and #11's dependencies). | Multiple |

## 🎯 Detailed Challenge Breakdown

### Challenge 1: Resource Governance - Storage
**Issue**: Cloud resources missing organizational compliance labels
**Focus**: Review governance standards for resource identification
**Best Practices**: 
• Implement consistent labeling strategies
• Follow organizational tagging policies
• Enable resource tracking and cost allocation

### Challenge 2: Resource Governance - Database  
**Issue**: Database resources not following compliance requirements
**Focus**: Ensure all resources meet governance standards
**Best Practices**:
• Apply standardized resource identification
• Maintain compliance across all resource types
• Enable proper resource categorization

### Challenge 3: Performance Optimization - Compute
**Issue**: Compute resources have restrictive performance limits
**Focus**: Review and optimize resource allocation settings
**Best Practices**:
• Configure appropriate performance limits
• Enable elastic scaling capabilities
• Optimize resource utilization

### Challenge 4: Application Configuration - Runtime
**Issue**: Application runtime parameters misaligned with infrastructure
**Focus**: Align application configuration with deployed resources
**Best Practices**:
• Maintain configuration consistency
• Use infrastructure-aware settings
• Implement proper service discovery

### Challenge 5: Communication Services - Publish
**Issue**: Message publishing capabilities restricted by access policies
**Focus**: Enable proper message delivery mechanisms
**Best Practices**:
• Configure appropriate service permissions
• Implement secure messaging patterns
• Enable cross-service communication

### Challenge 6: Network Security - Data Access
**Issue**: Network access controls too restrictive for data operations
**Focus**: Configure appropriate access permissions for data services
**Best Practices**:
• Implement least-privilege access
• Enable necessary data operations
• Maintain security while enabling functionality

### Challenge 7: Network Routing - Service Access
**Issue**: Network routing not optimized for cloud service connectivity
**Focus**: Optimize traffic routing for efficient service access
**Best Practices**:
• Implement efficient routing strategies
• Enable private service connectivity
• Optimize network traffic flows

### Challenge 8: API Service - Backend Integration
**Issue**: API gateway not properly connected to backend services
**Focus**: Establish proper service-to-service connections
**Best Practices**:
• Implement proper API integrations
• Enable service connectivity
• Configure backend service routing

### Challenge 9: API Security - Access Restrictions
**Issue**: API access controls not properly configured for network restrictions
**Focus**: Implement and enforce appropriate access policies
**Best Practices**:
• Restrict API access to authorized sources
• Implement network-based access controls
• Enable private API patterns

### Challenge 10: Process Automation - Scheduling
**Issue**: Automated processes not active
**Focus**: Activate automation workflows for operational efficiency
**Best Practices**:
• Enable event-driven automation
• Implement scheduled operations
• Configure proper automation triggers

### Challenge 11: System Integration - End-to-End
**Issue**: Service dependencies not fully operational
**Focus**: Ensure all system components work together properly
**Best Practices**:
• Validate cross-service functionality
• Test end-to-end workflows
• Ensure dependency resolution

### Challenge 12: Service Delivery - Final Verification
**Issue**: Complete system not delivering expected functionality
**Focus**: Validate full mission requirements are met
**Best Practices**:
• Verify end-to-end system operation
• Confirm all requirements satisfied
• Validate complete service delivery

## 🏆 Success Criteria

### Evaluation Results
When all challenges are completed, `bash eval.sh` should show:
```
ACCEPTED   : 12
INCOMPLETE : 0
```

### Final Flag
The final API call should return:
```json
{
  "flag": "ETHNUS{w3ll_4rch1t3ct3d_cl0ud_s3cur1ty_2025}"
}
```

</details>

---

## 📞 Support

- **Competitors**: Use AWS documentation, CloudWatch logs, and systematic troubleshooting
- **Instructors**: Run `remediate.sh` to see working configuration examples
- **Issues**: Check script output for specific error messages and context

## 📄 License

This project is designed for educational purposes as part of the Ethnus AWS training program.

---

**Good luck with your cloud architecture challenge! 🚀**
