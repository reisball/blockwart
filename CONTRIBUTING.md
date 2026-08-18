# Contributing

Contributions are welcome. Keep changes small, reviewable, and tied to a
tracked problem.

## Workflow

1. Search the existing issues before opening a new one.
2. Create or agree on an issue before implementation.
3. Work on a branch named after the issue, for example
   `feat/42-dashboard-widget` or `fix/42-dashboard-widget`.
4. Add focused tests and update documentation with the implementation.
5. Run the checks documented in [`docs/ci.md`](docs/ci.md).
6. Open a pull request that references the issue and explains the behavior,
   risks, and verification evidence.

Use concise commits such as:

```text
feat(catalog): Add dashboard widget. Refs #42
fix(auth): Reject stale session state. Refs #42
```

Use `Closes #42` only when the pull request is intended and approved to close
the issue.

## Security and test data

Never submit passwords, tokens, private keys, cookies, private catalog
exports, live environment files, or credentials disguised as test fixtures.
Examples must use reserved domains and documentation address ranges. Report
vulnerabilities through [`SECURITY.md`](SECURITY.md), not through a public
issue.
