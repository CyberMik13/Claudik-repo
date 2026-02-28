# CLAUDE.md

This file provides guidance for AI assistants (Claude and others) working in this repository. Keep this file up to date as the project evolves.

---

## Repository Overview

**Repository:** CyberMik13/Claudik-repo
**Status:** Newly initialized — no source files yet committed.

This CLAUDE.md was created to establish conventions, workflow expectations, and AI assistant guidelines before the first code is committed. Update each section as the project grows.

---

## Current State

- The repository contains no source code, configuration files, or dependencies yet.
- There is no build system, test runner, or CI/CD pipeline configured.
- This file (`CLAUDE.md`) is the first committed artifact.

When the project is bootstrapped, update the sections below with real values.

---

## Directory Structure

> Update this section once project files exist.

```
Claudik-repo/
├── CLAUDE.md          # This file — AI assistant guidance
└── (project files TBD)
```

Suggested structure to adopt (adjust to the chosen stack):

```
Claudik-repo/
├── CLAUDE.md
├── README.md
├── src/               # Application source code
├── tests/             # Test files
├── docs/              # Documentation
├── .github/           # GitHub Actions workflows
│   └── workflows/
├── .gitignore
└── <package manager manifest>   # e.g., package.json, pyproject.toml, go.mod
```

---

## Technology Stack

> Update this section once dependencies are chosen and committed.

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | TBD | |
| Framework | TBD | |
| Package Manager | TBD | |
| Test Runner | TBD | |
| Linter / Formatter | TBD | |
| CI/CD | TBD | |

---

## Development Workflow

### Getting Started

1. Clone the repository:
   ```bash
   git clone http://local_proxy@127.0.0.1:35129/git/CyberMik13/Claudik-repo
   cd Claudik-repo
   ```

2. Install dependencies (update command once stack is chosen):
   ```bash
   # e.g., npm install | pip install -e ".[dev]" | go mod download
   ```

3. Run the development server or entry point (update once defined):
   ```bash
   # e.g., npm run dev | python -m mypackage | go run ./cmd/...
   ```

### Branching Strategy

- `main` — stable, production-ready code. Never commit directly.
- `claude/<feature>-<session-id>` — branches created by AI assistants for automated tasks.
- `feature/<name>` — human-authored feature branches.
- `fix/<name>` — bug fix branches.

All changes should go through pull requests. Merge to `main` only after review.

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short description>

[optional body]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`

Examples:
```
feat(auth): add JWT login endpoint
fix(parser): handle empty input without panic
docs: update CLAUDE.md with stack details
chore: configure eslint and prettier
```

---

## Running Tests

> Update this section once a test runner is configured.

```bash
# Placeholder — replace with actual command
# e.g.:
#   npm test
#   pytest
#   go test ./...
```

- All new features must include tests.
- Tests must pass before merging a pull request.
- Aim for meaningful coverage, not just high numbers.

---

## Linting and Formatting

> Update this section once linting tools are configured.

```bash
# Placeholder — replace with actual command
# e.g.:
#   npm run lint
#   ruff check . && ruff format --check .
#   golangci-lint run
```

- Code must pass linting before merging.
- Auto-format on save is encouraged.
- Do not suppress linting rules without a documented reason.

---

## Build and Deployment

> Update this section once a build process exists.

```bash
# Placeholder — replace with actual command
```

---

## Key Conventions

### General

- **Keep functions small and focused.** A function should do one thing.
- **Avoid premature abstraction.** Don't extract helpers until the pattern repeats at least 3 times.
- **No commented-out code.** Remove dead code; version control preserves history.
- **No magic numbers.** Use named constants with explanatory names.
- **Fail loudly.** Prefer explicit errors over silent failures.

### Naming

- Use descriptive, intention-revealing names.
- Avoid abbreviations unless universally understood (`url`, `id`, `db`).
- Follow the naming conventions of the chosen language (e.g., `camelCase` for JS/Go, `snake_case` for Python).

### Error Handling

- Handle errors at the call site; don't swallow them.
- Include enough context in error messages to diagnose the problem.
- Distinguish between user-facing errors and internal errors.

### Security

- Never commit secrets, API keys, or credentials. Use environment variables.
- Validate all external input (user input, API responses, file contents).
- Follow OWASP guidelines for web applications.
- Dependency updates should be reviewed, not blindly applied.

---

## AI Assistant Guidelines

### What AI Assistants Should Do

- **Read before editing.** Always read a file before modifying it.
- **Make minimal, targeted changes.** Only change what is necessary for the task.
- **Follow existing conventions.** Match the style of surrounding code.
- **Run tests before committing.** Ensure nothing is broken.
- **Write clear commit messages.** Follow the Conventional Commits format above.
- **Push to the correct branch.** Use `claude/<feature>-<session-id>` branches.
- **Update CLAUDE.md** when adding new tools, workflows, or conventions.

### What AI Assistants Should NOT Do

- Do not push directly to `main`.
- Do not commit `.env` files, secrets, or credentials.
- Do not delete files without understanding their purpose.
- Do not introduce new dependencies without noting them in the PR description.
- Do not suppress linter warnings without explanation.
- Do not create files unless they are clearly necessary.
- Do not add error handling, fallbacks, or validation for scenarios that cannot happen.
- Do not refactor code beyond the scope of the current task.

### Git Operations for AI Assistants

```bash
# Always push to the designated branch with upstream tracking
git push -u origin claude/<feature>-<session-id>

# On network failure, retry with exponential backoff:
# wait 2s → retry → wait 4s → retry → wait 8s → retry → wait 16s → retry
```

---

## Environment Variables

> Update this section once environment variables are defined.

| Variable | Required | Description |
|----------|----------|-------------|
| (none yet) | — | — |

Store environment variables in a `.env` file locally (never committed) and document them here. Use `.env.example` as a committed template with placeholder values.

---

## CI/CD

> Update this section once GitHub Actions or another CI system is configured.

Planned checks to run on every pull request:
- Linting
- Tests
- Build verification

---

## Contributing

1. Create a branch from `main`.
2. Make changes following the conventions in this file.
3. Ensure tests pass and linting is clean.
4. Open a pull request with a clear description.
5. Address review feedback.

---

*Last updated: 2026-02-28 by Claude (AI assistant) — initial CLAUDE.md creation for empty repository.*
