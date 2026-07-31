---
name: Bug report
about: Report incorrect behaviour in Spindle
title: '[BUG] '
labels: bug
assignees: ''

---

<!--
STOP if this is a security vulnerability.

Do not open a public issue for anything that lets an attacker read or forge a
command, bypass the pin check, replay a frame, or reuse a nonce. See SECURITY.md
and email rex@xraph.com instead.

If you are unsure whether it is a security issue, treat it as one.
-->

## Describe the bug

A clear and concise description of what the bug is.

## To Reproduce

Steps to reproduce the behavior:
1. ...
2. ...
3. ...

## Expected behavior

What you expected to happen, and — if relevant — which part of SPEC.md led you to
expect it.

## Actual behavior

What actually happened.

## Environment

- Spindle Version: [e.g. v0.1.0]
- Go Version: [e.g. 1.25.0]
- OS: [e.g. Ubuntu 22.04, macOS 14.0]
- Architecture: [e.g. amd64, arm64]
- Transport: [e.g. MQTT, in-process, other]

## Code Sample

```go
// Minimal code to reproduce the issue.
```

## Handshake context

Only if the problem involves a handshake or a frame:

- Which side failed: controller or device?
- Was the device commissioning (`Commissioning: true`) or pinned?
- Do both sides use the same scope? An empty scope on one side and a real one on
  the other fails every MAC check, and that is the intended behaviour.
- Do both sides pass the same AAD for the frame class?

## Additional context

Stack traces, logs, related issues.
