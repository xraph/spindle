## Description

<!-- Provide a brief description of the changes in this PR -->

## Type of Change

<!-- Mark the relevant option with an 'x' -->

- [ ] feat: A new feature
- [ ] fix: A bug fix
- [ ] docs: Documentation only changes
- [ ] refactor: A code change that neither fixes a bug nor adds a feature
- [ ] perf: A code change that improves performance
- [ ] test: Adding missing tests or correcting existing tests
- [ ] build: Changes that affect the build system or external dependencies
- [ ] ci: Changes to CI configuration files and scripts
- [ ] chore: Other changes that don't modify src or test files

## Breaking Change

- [ ] No
- [ ] Yes — API only
- [ ] Yes — **wire format**, which means every deployed device must re-provision

<!-- If breaking, describe the change and the migration path -->

## Security-sensitive areas

<!-- Tick any file you touched. If you tick one, state below which property you
     believe still holds and which test demonstrates it. -->

- [ ] `session.go` / `replay.go` — sequence numbers drive the AEAD nonce
- [ ] `handshake.go` — the pin check decides which controller a device obeys
- [ ] `suite.go` — prologue construction and scope binding
- [ ] `attestation.go` — field framing
- [ ] `fingerprint.go` — the wordlist must stay 256 complete, unique, stable
- [ ] None of the above

**Property preserved / test that shows it:**

## Checklist

- [ ] My code follows the project's code style
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] SPEC.md is updated if observable protocol behaviour changed
- [ ] My changes generate no new warnings or errors
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] Any value both endpoints derive is asserted equal across them, not just
      checked on one side
- [ ] I confirmed new security tests fail when the property is broken
- [ ] `go test -race ./...` passes
- [ ] `golangci-lint run` passes
- [ ] `govulncheck ./...` passes

## Testing

<!-- Describe the tests you ran to verify your changes -->

## Related Issues

Closes #

## Additional Notes

<!-- Add any additional notes or context here -->
