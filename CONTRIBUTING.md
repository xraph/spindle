# Contributing to Spindle

Thanks for your interest. Spindle is a cryptographic library, so a few of the
norms here are stricter than in a typical Go project — those differences are
called out below rather than left implicit.

Before proposing a change to the protocol itself, read [SPEC.md](SPEC.md). Most
questions about why something is the way it is are answered there, including the
things that are deliberately *not* guaranteed (§8).

## Code of Conduct

Be respectful and constructive. Harassment or abusive behaviour is not tolerated.

## Development Setup

```bash
git clone https://github.com/xraph/spindle.git
cd spindle
go mod download
go test -race ./...
```

Requires Go 1.25 or newer, as declared in `go.mod`.

Optional but expected before opening a PR:

```bash
golangci-lint run          # config is in .golangci.yml; includes gosec
govulncheck ./...
```

## Security-sensitive changes

**Do not open a public pull request for a vulnerability fix.** See
[SECURITY.md](SECURITY.md) for coordinated disclosure.

For ordinary changes, these areas need review out of proportion to their diff
size, because a subtle mistake in any of them is exploitable rather than merely
wrong:

| Area | Why |
|---|---|
| `session.go`, `replay.go` | Sequence numbers drive the AEAD nonce directly. A mistake here is nonce reuse. |
| `handshake.go` | The pin check is the only thing deciding *which* controller a device obeys. |
| `suite.go` | Prologue construction; a length-prefix change can make two scopes collide. |
| `attestation.go` | Field framing; unprefixed concatenation lets one signature mean two things. |
| `fingerprint.go` | The wordlist must stay 256 complete, unique entries, and stable. |

If you change any of them, say in the PR description what property you believe
still holds and which test demonstrates it.

## Testing Guidelines

Ordinary Go norms apply — table-driven where it helps, `t.Helper()` in helpers,
descriptive subtest names. Two additions specific to this project:

**Assert across endpoints, not within one.** Nearly every real bug this codebase
has had was a value two sides were supposed to compute identically and did not:
diverging transcripts, a fingerprint mixing in a value only one side knew, a
wordlist that rendered differently than it hashed. A test that checks one side in
isolation would have passed in every one of those cases. If your change produces
a value both peers derive, assert they match.

**Tests must fail for the right reason.** When adding a test for a security
property, confirm it fails when the property is broken — mutate the line and
watch it go red before you trust it green.

Run with `-race`. The session is documented as safe for concurrent use, and a
data race in the frame path is a nonce-reuse bug, not a flake.

## Code Quality Standards

- `gofmt` clean; CI enforces it.
- `golangci-lint run` clean against the committed config.
- No `TODO`/`FIXME`/`XXX` on `main` — CI rejects them.
- No debug prints in non-test code.
- Comments explain *why*, not *what*. A comment asserting a property that nothing
  tests is a liability; either test it or do not claim it.
- `//nolint` directives must carry a reason.

Note that `nlreturn` and `wsl_v5` are intentionally disabled in `.golangci.yml`.
They are whitespace-placement linters, and the churn they demand across this
package is not worth the diff noise in security-critical code. Every substantive
linter, including `gosec`, is on.

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: A new feature (triggers minor version bump)
- `fix`: A bug fix (triggers patch version bump)
- `docs`: Documentation only changes
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement (triggers patch version bump)
- `test`: Adding or updating tests
- `build`: Changes to build system or dependencies
- `ci`: Changes to CI configuration
- `chore`: Other changes that don't modify src or test files
- `revert`: Reverts a previous commit

### Breaking Changes

Add `BREAKING CHANGE:` in the footer or append `!` after the type:

```
feat!: derive the fingerprint from the handshake binding alone

BREAKING CHANGE: FingerprintWords no longer takes a liveness argument.
```

Anything that changes bytes on the wire is a **protocol** break, not just an API
break. Spindle has no version negotiation by design, so a wire change means every
deployed device must re-provision. Say so explicitly in the footer.

### Examples

```
fix(session): reject a sequence number past MaxSeq instead of wrapping

Wrapping reuses a (key, nonce) pair under ChaCha20-Poly1305, which leaks
the keystream and the authenticator key.

Fixes #12
```

```
docs(spec): correct the claim that both endpoints hold the liveness seed

Only the controller generates it, so a fingerprint binding it could never
agree across the two sides.
```

## Pull Request Process

1. Fork and branch from `main`.
2. Make the change, with tests.
3. Run `go test -race ./...`, `golangci-lint run`, and `govulncheck ./...`.
4. Open the PR with a description covering what changed, why, and — for anything
   in the table above — which property still holds and what proves it.
5. CI must be green before review.

## Documentation

If a change alters observable protocol behaviour, update [SPEC.md](SPEC.md) in
the same PR. A spec that lags the code is worse than no spec: it is the document
a reviewer trusts.

Keep SPEC.md §8 honest. If your change introduces a new limitation, add it there
rather than leaving it for someone to discover.

## Release Process

Maintainers tag releases as `vX.Y.Z` following semantic versioning. While the
module is `v0.x`, the API may change between minors; breaking changes are called
out in the release notes.

## Getting Help

Open a discussion or an issue. For anything that might be a vulnerability, email
rex@xraph.com first — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0 — see [LICENSE](LICENSE).
