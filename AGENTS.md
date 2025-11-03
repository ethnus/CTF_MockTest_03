# Workspace Guidance
This guide combines our repository conventions with a high-level brief of the Serverless Resiliency Lab challenge so changes stay predictable and the troubleshooting effort remains focused.

## Repository Guidelines

### Project Structure & Module Organization
Keep the repository root minimal and group implementation code inside `src/`. Shared foundations (config, adapters, environment shims) belong in `src/core/`, while task-specific logic lives under `src/modules/<feature>/`. Store automation scripts in `scripts/`, long-form references in `docs/`, reusable assets (mock data, prompts, media) in `assets/`, and test fixtures beside the specs they support inside `tests/`. When you add a new area, create a short `README.md` in that folder describing its contract and dependencies.

### Build, Test, and Development Commands
- `npm install`: install toolchain dependencies before your first build or whenever `package.json` changes.
- `npm run dev`: launch the local development environment; enables hot reload for rapid iteration.
- `npm run build`: produce an optimized bundle for competition-ready delivery; confirm it finishes cleanly before requesting review.
- `npm test`: execute the unit and integration suite; use `npm test -- --watch` while iterating on a module.
- `npm run lint`: run the static analysis stack (ESLint + Prettier) and auto-fix style issues where possible.

### Coding Style & Naming Conventions
Favor TypeScript for all new logic, using 2-space indentation, trailing commas, and double quotes. Export one primary symbol per file; name files in kebab-case (e.g., `session-manager.ts`) and classes in PascalCase. Centralize constants in `src/core/constants.ts` and keep prompt templates under `assets/prompts/`. Always run `npm run lint` before committing to enforce ESLint and Prettier rules.

### Testing Guidelines
Use Vitest for unit coverage and Playwright for end-to-end paths. Mirror the source tree inside `tests/` (e.g., `tests/modules/session-manager.spec.ts`). Aim for ≥80% statement coverage for each module; add a coverage note in your PR if a lower threshold is justified. Include regression tests for every bug fix and stub external calls with `msw` or local fakes to keep the suite deterministic.

### Commit & Pull Request Guidelines
Follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.) so the changelog stays machine-readable. Scope commits narrowly—one logical change per commit—and rebase onto `main` before opening a PR. Each PR should include: a concise summary, linked issue or task ID, screenshots or terminal output for UI/CLI changes, and a checklist confirming `npm run build`, `npm test`, and `npm run lint` all pass locally.

## Serverless Resiliency Lab Notes

### Mission Summary
Restore a private ingestion pipeline that accepts JSON telemetry, writes to DynamoDB, archives to S3, and remains fully private inside a managed VPC. Ten seeded misconfigurations must be identified and remediated using the lab IAM role (default `LabRole`) with AWS CLI v2, Python 3, and `zip` available locally.

### Architecture Snapshot
- Private API Gateway endpoint fronting the ingestion API.
- Lambda writer running inside the VPC and using customer-managed KMS encryption.
- DynamoDB table (on-demand) for primary storage plus S3 bucket for durable backup.
- EventBridge rule sending heartbeats to the Lambda every 10 minutes.
- Required VPC interface endpoints so traffic never leaves the private network.

### Investigation Themes
- **Data Protection:** Enforce KMS usage, resource tagging, and encryption defaults.
- **Resilience:** Validate database recovery options and heartbeat coverage.
- **Private Connectivity:** Confirm VPC endpoints and routing satisfy private access.
- **Application Configuration:** Verify Lambda environment, IAM permissions, and integrations keep telemetry flowing.

### Mission Playbook
1. Orientation: assume the lab account/role and inspect `state/serverless-lab-state.json` for provisioned identifiers.
2. Data Controls: audit encryption posture, key policies, and tagging alignment.
3. Network Paths: prove private endpoints and routes work end to end.
4. Runtime Integrity: test Lambda configuration and downstream writes to DynamoDB/S3.
5. Availability Signals: reinstate EventBridge heartbeat or other automated probes.
6. Access Boundaries: restrict API Gateway invocation to the intended VPC endpoint.
7. Proof of Completion: demonstrate private API access with successful writes to both storage layers.

### Cost & Teardown Highlights
- Serverless/on-demand footprint keeps lab costs under roughly USD $5 without sustained load.
- EventBridge schedule triggers ~18 times per 3-hour session, staying within free-tier limits.
- DynamoDB on-demand accrues negligible charges when idle.
- Environment auto-tears down after the lab; manual cleanup is possible via state file resource IDs.

### Troubleshooting Shortlist
- Keep the state manifest nearby for resource IDs (VPC, endpoints, keys).
- Run `aws sts get-caller-identity` before changes to confirm the active lab role.
- Edit policies via `--cli-input-json` or Python helpers to avoid shell quoting issues.
- After each fix, run targeted AWS CLI describe calls to verify the correction.
