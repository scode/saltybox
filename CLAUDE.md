# PR titles

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) style. This is enforced by CI and
used by git-cliff for changelog generation.

Allowed types: `feat`, `fix`, `docs`, `doc`, `perf`, `refactor`, `style`, `test`, `chore`, `ci`, `revert`. Scope is
optional. Examples: `feat: add user login`, `fix(parser): handle empty input`.

Type must reflect user-visible behavior, not implementation activity. CLI interface/behavior changes must be `feat`,
`fix`, or `perf` (use `!` when breaking), not `refactor`.

Every PR body must contain exactly one of `changelog: include` or `changelog: skip`. This is enforced by CI.

# Error messages

Prefer specific error messages over deduplication. It is fine to have functionally redundant error returns if they
provide more precise diagnostics for different failure scenarios (e.g., "likely truncated" vs. generic "unrecognized").

# Releasing

When the user asks to "make a release" or "cut a release", follow the Releasing section of `CONTRIBUTING.md`.
