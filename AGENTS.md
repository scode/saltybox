# SPEC.md compliance

`SPEC.md` specifies user-visible behavior (the command-line interface and the on-disk file formats) and a few
project-level rules, such as saltybox being a program rather than a library. Changes must comply with it. Any change
that alters user-visible behavior must update `SPEC.md` in the same change. If the implementation and `SPEC.md`
disagree, that is a bug: fix the implementation to match the spec — unless the task is intentionally changing behavior,
in which case update `SPEC.md` to match as part of the change. Behavior `SPEC.md` does not cover is
existing-but-unspecified; when a change touches such behavior, specify it (including its pre-existing behavior) in the
same change.

# Checks

Run the checks CI enforces locally before creating or updating a PR, and again after fixing review findings:

- `cargo fmt -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features --all-targets`
- `cargo doc --no-deps --all-features`
- `dprint check`

Plain `cargo doc` suffices for the documentation check: rustdoc's lints (such as public documentation intra-doc-linking
a private item) are denied via the `[lints.rustdoc]` table in `Cargo.toml`, so they fail the build rather than scrolling
past as warnings.

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

# Chores

## Upgrading pinned GitHub Actions

`SPEC.md` (Build integrity) requires every action from outside this repository to be referenced by full commit SHA, with
its version in a trailing comment. Nothing upgrades these automatically (Dependabot is not configured for actions), so
upgrade them by hand:

- Pick the new version tag from the action's releases (for example `v5.2.0`).
- Resolve the tag to a commit with
  `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object.type + " " + .object.sha'`. If the type is `tag` (an
  annotated tag), that SHA is the tag object, not the commit; dereference it with
  `gh api repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha`.
- Replace the SHA and the trailing version comment on every `uses:` line for that action in `.github/workflows/`.
- Check that `grep -rn 'uses:' .github/workflows | grep -vE '@[0-9a-f]{40} # '` lists only local `./` references.

The actions in `release.yml` are written by `dist`, which takes their SHAs from `[dist.github-action-commits]` in
`dist-workspace.toml`. For those, update the SHA and version comment there and regenerate the workflow instead of
editing `release.yml` by hand.

# Releasing

When the user asks to "make a release" or "cut a release", follow the Releasing section of `CONTRIBUTING.md`.
