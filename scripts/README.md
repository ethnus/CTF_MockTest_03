# scripts

Automation entry points for the Serverless Resiliency Lab AWS project.

- `init.sh`: Bootstraps the lab with intentional faults (read-only IAM role compatible). Use `--reinit` to re-introduce faults on an existing deployment using the state manifest.
- `eval.sh`: Executes the local remediation checks and prints a generic, colorized table of tasks. Use `--verbose` for instructor diagnostics.
- `remediate.sh`: Instructor-only script to restore the reference solution.
- `teardown.sh`: Deletes provisioned resources recorded in the state manifest.

All scripts assume the AWS CLI is configured for the managed lab role and respect the `STATE_FILE` environment variable for custom state paths.
