# Repository Guidelines
This guide captures the baseline expectations for contributions to the IS2025 workspace so changes stay predictable and easy to review.

## Project Structure & Module Organization
Keep the repository root minimal and group implementation code inside `src/`. Shared foundations (config, adapters, environment shims) belong in `src/core/`, while task-specific logic lives under `src/modules/<feature>/`. Store automation scripts in `scripts/`, long-form references in `docs/`, reusable assets (mock data, prompts, media) in `assets/`, and test fixtures beside the specs they support inside `tests/`. When you add a new area, create a short `README.md` in that folder describing its contract and dependencies.

## Build, Test, and Development Commands
- `npm install`: install toolchain dependencies before your first build or whenever `package.json` changes.
- `npm run dev`: launch the local development environment; enables hot reload for rapid iteration.
- `npm run build`: produce an optimized bundle for competition-ready delivery; confirm it finishes cleanly before requesting review.
- `npm test`: execute the unit and integration suite; use `npm test -- --watch` while iterating on a module.
- `npm run lint`: run the static analysis stack (ESLint + Prettier) and auto-fix style issues where possible.

## Coding Style & Naming Conventions
Favor TypeScript for all new logic, using 2-space indentation, trailing commas, and double quotes. Export one primary symbol per file; name files in kebab-case (e.g., `session-manager.ts`) and classes in PascalCase. Centralize constants in `src/core/constants.ts` and keep prompt templates under `assets/prompts/`. Always run `npm run lint` before committing to enforce ESLint and Prettier rules.

## Testing Guidelines
Use Vitest for unit coverage and Playwright for end-to-end paths. Mirror the source tree inside `tests/` (e.g., `tests/modules/session-manager.spec.ts`). Aim for ≥80% statement coverage for each module; add a coverage note in your PR if a lower threshold is justified. Include regression tests for every bug fix and stub external calls with `msw` or local fakes to keep the suite deterministic.

## Commit & Pull Request Guidelines
Follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.) so the changelog stays machine-readable. Scope commits narrowly—one logical change per commit—and rebase onto `main` before opening a PR. Each PR should include: a concise summary, linked issue or task ID, screenshots or terminal output for UI/CLI changes, and a checklist confirming `npm run build`, `npm test`, and `npm run lint` all pass locally.
