# Security Policy

Spindle is a cryptographic library. Bugs here are security bugs by default, so
please read [SPEC.md](SPEC.md) — particularly §2 (threat model) and §8 (residual
risks) — before reporting, since several properties people expect are explicitly
out of scope rather than broken.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

The API is not yet stable. While the module is `v0.x`, security fixes land on the
latest minor only — there is no backport branch.

## Reporting a Vulnerability

### Do NOT:

- Open a public issue
- Post in discussions
- Share details publicly before a patch is released

### DO:

1. **Email**: rex@xraph.com, or open a GitHub Security Advisory on this
   repository.
2. **Provide details**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information

### What to Expect:

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 7-14 days
  - Medium: 14-30 days
  - Low: 30-90 days

### Disclosure Timeline:

1. Vulnerability reported and confirmed
2. Patch developed and tested
3. Security advisory drafted
4. Patch released
5. Public disclosure (coordinated)

We follow a 90-day disclosure timeline unless a critical severity warrants
faster action, coordination with other projects is needed, or circumstances are
otherwise exceptional.

## What is in scope

A report is in scope if it shows any of the following:

- A way to read or forge a command without holding an endpoint's private key.
- A handshake completing against a peer whose static key was not the pinned one.
- A replayed frame being accepted, or a fresh frame being wrongly rejected as a
  replay.
- Two different deployment scopes producing the same prologue, or two endpoints
  deriving different bindings from the same handshake.
- An attestation from one session verifying in another.
- Any path that reuses a `(key, nonce)` pair, or that advances a sequence number
  past `MaxSeq` rather than erroring.
- A commissioning fingerprint that fails to change when a key is substituted.

## What is out of scope

These are documented properties, not defects. Reporting them is welcome as
discussion, but they will not be treated as vulnerabilities:

- **Availability.** A broker that drops or delays frames denies service. Spindle
  detects this; it cannot prevent it.
- **Traffic analysis.** Frame sizes and timing are visible to the broker. There
  is no padding or cover traffic.
- **A commissioning-mode device accepting any controller.** That is what
  commissioning mode is for. It is guarded by physical operator presence and the
  fingerprint comparison, and it is explicitly opt-in
  (`DeviceConfig.Commissioning`).
- **Compromise of a stored private key.** Key storage is the caller's
  responsibility; Spindle never persists key material.
- **No formal model.** The Noise pattern is verified upstream, but the
  composition around it is not. This is stated in SPEC.md §8 and is the largest
  known open item — a proof, or a counter-example, is very welcome as a
  contribution.

## Operating it safely

### 1. Pin in both directions

The controller pins the device static at commissioning; the device pins the
controller static. An empty `ControllerStatic` is an error, never an implicit
"accept anything". If you find yourself setting `Commissioning: true` outside a
physically supervised provisioning window, stop — that suspends the only check
that says *which* controller a device will obey.

### 2. Treat the sequence path as load-bearing

Sequence numbers drive the receiving nonce directly. Three rules make that safe,
and all three are tested:

- A frame failing authentication never marks its sequence as seen.
- Sequence 0 is a valid first frame.
- Sequence exhaustion returns `ErrSeqExhausted`; it never wraps.

Any change to `session.go` or `replay.go` deserves review out of proportion to
its size.

### 3. Use a distinct AAD per traffic class

Derive one `AAD(label)` per class of frame and use it consistently on both ends.
Sharing a label across classes lets a captured frame of one kind be accepted as
another.

### 4. Bind your scope

Pass a real deployment scope. It goes into the Noise prologue, so a device
provisioned for one scope cannot complete a handshake for another. An empty scope
is legitimate only during commissioning, when the device does not yet know where
it belongs.

### 5. Rotate out of band

There is no in-band key rotation, deliberately — an in-band recovery path is an
in-band takeover path. Revoke and re-provision.

### 6. Keep dependencies current

`govulncheck` runs in CI against `flynn/noise` and `golang.org/x/crypto`. A
vulnerability in either is a vulnerability in Spindle.

## Security Testing

The test suite covers both handshake roles, scope and pinning rejection, replay
and out-of-order delivery, forged-frame window behaviour, sequence exhaustion,
attestation tampering, and wordlist completeness.

```bash
go test -race ./...
golangci-lint run          # includes gosec
govulncheck ./...
```

CI runs all three on every push and pull request.

## Questions

For anything that is not a vulnerability report, open a discussion or an issue.
For anything that might be one, email rex@xraph.com first.
