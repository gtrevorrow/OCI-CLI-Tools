# Contributing

Thanks for helping improve this project! A few guidelines to keep changes smooth and releases automatic.

## Workflow
- Target branch: `feature/woci-session-manager` (or topic branches) → PR into `main`.
- Tests: run `python -m pytest -q` before submitting.
- Keep changes small and focused; include docs/tests when behavior changes.

## Commit messages (Conventional Commits)
Use `type(scope?): short description` and optional body/footer. Examples:
- `feat: add token exchange retry`
- `fix(profile): handle missing redirect_port`
- `chore!: drop Python 3.8`
Breaking changes: add `!` after type/scope or include a `BREAKING CHANGE:` footer.

### Optional tooling
- **Commitizen**: `pip install .[dev]` then `cz check` to validate messages or `cz commit` for a guided prompt. Config lives in `pyproject.toml`.
- **Sign-off**: if you need DCO-style trailers, use `git commit -s` (Commitizen preserves trailers you add in the footer).

## Releases (semantic-release)
- `main` is the release branch. On merge to `main`, the GitHub Actions workflow tags `v<version>`, updates `CHANGELOG.md`, and creates a GitHub release. No PyPI publishing is configured.
- To preview locally: `python -m semantic_release publish --noop --verbosity=DEBUG`.

## Sign-off / DCO
- If your organization requires DCO, sign commits with `git commit -s` to add the `Signed-off-by` trailer.
- Enforcement is managed via repository settings (branch protection or a DCO check). This repo does not currently enforce it automatically, but signed commits are welcome.

## Pull requests
- Describe the change, testing performed, and any breaking impact.
- Keep PRs aligned with the Conventional Commit style (the merge commit/tagging relies on it for version bumps).
