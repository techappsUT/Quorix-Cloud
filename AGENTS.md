# Repository Guidelines

## Project Structure & Module Organization
- `backend/` houses the Go services for APIs, compliance rules, and inventory logic; it loads configuration from `.env` and stores reusable policies under `rules/`.
- `frontend/` contains the React + TypeScript SPA; UI components live under `src/components`, route definitions under `src/routes`, and static assets in `public/`.
- `cartography/` mirrors the Lyft Cartography engine that powers asset ingest; manage it in an isolated virtualenv and keep tests under `tests/unit` and `tests/integration`.
- `cdk/` defines optional AWS CDK stacks with entrypoints in `bin/` and constructs in `lib/`; synth outputs feed into the docker-compose deployments.
- Compose files (`docker-compose*.yaml`) and `zeus-proxy/` orchestrate local and release containers—update them whenever service ports, images, or env vars change.

## Build, Test, and Development Commands
- `make quick-deploy` boots the full stack with Docker Compose using the variables in `.env`.
- `docker-compose -f docker-compose.dev.yaml --env-file .env.dev up --build` rebuilds backend and frontend in development mode with hot reload.
- `cd backend && go run .` starts the API locally; pair it with `go test ./...` before pushing Go changes.
- `cd frontend && yarn && yarn start` installs dependencies and serves the UI; `yarn build` generates the static bundle used by production containers.
- `cd cartography && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` prepares the ingest engine; `make test` runs lint, unit, and integration suites.

## Coding Style & Naming Conventions
- Go code must remain `gofmt`/`goimports` clean, with camelCase locals and PascalCase exported symbols; use package-level interfaces sparingly and prefer dependency injection through constructors.
- Frontend modules follow TypeScript strictness in `tsconfig.json`; components use PascalCase filenames, hooks use `useCamelCase`, and Tailwind utility classes should stay in JSX rather than CSS files.
- Python in `cartography/` adheres to 120-character lines, snake_case functions, and the mypy profiles defined in `setup.cfg`; run `pre-commit run --all-files` when touching this module.

## Testing Guidelines
- Place Go tests alongside code as `_test.go` files and favour table-driven cases; `go test ./...` must pass cleanly before review.
- Co-locate frontend specs as `.test.tsx` files near components and execute `yarn test --watchAll=false` for CI-parity runs.
- Extend `cartography/tests/unit` for fast coverage and `tests/integration` when Neo4j fixtures are required; the coverage floor is 30%, so avoid regressions when adding modules.
- When changing compose or CDK assets, add the output of `docker-compose config` or `cdk diff` to the PR notes to compensate for limited automated coverage.

## Commit & Pull Request Guidelines
- Follow the existing log style: concise imperative subjects with optional issue references, e.g. `Improve asset sync (#342)`.
- Keep commits focused and avoid committing generated bundles; rely on Docker builds to produce runtime artifacts.
- Pull requests should include a problem statement, testing evidence (commands run or UI captures), linked issues, and a rollback note for infra-heavy work.
- Attach sanitized screenshots or GIFs for UI-facing updates and call out any manual migration steps.

## Security & Configuration Tips
- Never commit real cloud credentials—use `.env.dev` samples and document any new keys in PR descriptions.
- Rotate Neo4j/Postgres volumes with `make clean` before sharing snapshots or resetting local data.
- Follow `SECURITY.md` for vulnerability disclosure and route exploitable findings to `founders@zeuscloud.io` instead of filing public issues.
