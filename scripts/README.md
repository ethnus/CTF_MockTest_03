# scripts

Automation entry points for the Serverless Resiliency Lab AWS project.

- `init.sh`: Bootstraps the lab with intentional faults (read-only IAM role compatible).
- `eval.sh`: Executes the local remediation checks and prints the deterministic flag when all controls pass.
- `report.sh`: Wraps `eval.sh`, verifies AWS CLI v3 credentials, and logs hashed participant identifiers plus results to `state/results.db`.
- `remediate.sh`: Instructor-only script to restore the reference solution.

All scripts assume the AWS CLI is configured for the managed lab role and respect the `STATE_FILE` environment variable for custom state paths.
