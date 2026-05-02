# tests/

QA artifacts for RichardMedina Security Hardening.

- `qa-matrix-v{VERSION}.md` — manual QA matrix per agency CLAUDE.md §5.3. Copy to a new file for each release, fill in results, and commit alongside the version bump.
- `unit/` — PHPUnit tests for pure functions and value objects. (Empty in v0.1.)
- `integration/` — `wp-env` / LocalWP integration tests. (Empty in v0.1.)
- `fixtures/` — sample payloads, expected log lines, etc.

## Running the QA matrix

1. Copy `qa-matrix-v0.1.0.md` to `qa-matrix-v{NEW_VERSION}.md` for the next release.
2. Reset all "Result" cells.
3. Walk through every row on staging.
4. Commit the filled-in file with the release tag.
