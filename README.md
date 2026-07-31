# spindle

[![CI](https://github.com/xraph/spindle/actions/workflows/ci.yml/badge.svg)](https://github.com/xraph/spindle/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/xraph/spindle.svg)](https://pkg.go.dev/github.com/xraph/spindle)
[![Go Report Card](https://goreportcard.com/badge/github.com/xraph/spindle)](https://goreportcard.com/report/github.com/xraph/spindle)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

End-to-end secure channel for remote device control across an untrusted message
broker.

```
go get github.com/xraph/spindle
```

`Noise_IK_25519_ChaChaPoly_BLAKE2b`, plus the two things a pub/sub deployment
needs on top of it: out-of-order-tolerant replay rejection, and commissioning
primitives that bind a device key to a physical act of provisioning.

## Why not just use TLS

TLS terminates at the broker. MQTT, AMQP and friends hand the broker plaintext
for every message that passes through it. When the message opens a valve, the
broker is inside your trust boundary whether you meant it to be or not.

Spindle keeps the plaintext at the endpoints. A compromised broker can drop,
reorder, or replay ciphertext; it cannot read a command or forge one.

## Why not just use Noise

Mostly you should — the channel here *is* stock Noise_IK, and the cryptography is
unmodified. Two things are missing from a bare Noise handle:

**Ordering.** Noise's `CipherState` assumes an ordered stream. Pub/sub gives you
nothing of the kind. Spindle carries an explicit sequence number and drives the
receiving nonce from the wire, gated by a sliding window — with the rules that
make that safe (a forged frame never consumes a window slot; sequence exhaustion
is an error, not a wrap).

**Responder-side pinning.** IK tells the device that the controller is authentic,
not that it is the *expected* controller. Spindle checks the delivered static
against the commissioned one, in constant time.

See [SPEC.md](SPEC.md) for the threat model, the full construction, and an honest
list of what is not guaranteed.

## Usage

Commissioning happens once, out of band: the controller records the device's
static public key, the device records the controller's. Everything below assumes
that already happened.

### Controller

```go
c, err := spindle.NewController(spindle.ControllerConfig{
    Identity:     identity,              // *spindle.ControllerIdentity
    DeviceStatic: dev.StaticPubKey,      // pinned at commissioning
    Scope:        dev.Scope,             // bound into the Noise prologue
})
if err != nil {
    return err
}

msg1, err := c.Hello(challengeNonce)     // encrypted payload
if err != nil {
    return err
}
send(msg1)

session, devicePayload, err := c.Complete(recv())
if err != nil {
    return err
}
```

### Device

```go
d, err := spindle.NewDevice(spindle.DeviceConfig{
    Keys:             keys,                    // *spindle.DeviceKeys
    ControllerStatic: provisioned.CtrlStatic,  // pinned at commissioning
    Scope:            provisioned.Scope,
})
if err != nil {
    return err
}

challenge, err := d.ReadHello(recv())    // fails with ErrControllerNotPinned
if err != nil {                          // if this is the wrong controller
    return err
}

msg2, session, err := d.Welcome(attestationPayload)
if err != nil {
    return err
}
send(msg2)
```

### Commissioning

A device with no pin yet cannot enforce one. `Commissioning` suspends the pin
check for exactly that first handshake — valid only while the device is under
physical operator control, because in this mode it will complete a handshake with
any controller that knows its static public key.

```go
d, err := spindle.NewDevice(spindle.DeviceConfig{
    Keys:          keys,
    Commissioning: true,   // mutually exclusive with ControllerStatic
    Scope:         scope,
})
// ... ReadHello, then show the operator:
fp := spindle.FingerprintWords(d.AttestationBinding())

// Only after the operator confirms the same six words on both ends:
seal(d.AdoptedControllerStatic())
```

The flag must be set explicitly. An empty `ControllerStatic` is an error, not an
invitation — a config that forgot to set the pin fails closed.

Both endpoints derive the fingerprint from `AttestationBinding()` and nothing
else, which is tested to be byte-identical across them. Anything else you want
bound must go *into* the transcript: folding in a value only one endpoint knows
guarantees the two fingerprints disagree, which defeats the comparison they exist
to support.

### Carrying traffic

The session owns sequencing. Derive the AAD once per traffic class and pass the
same value on both endpoints.

```go
var controlAAD = spindle.AAD("app/control/v1")

frame, err := session.Seal(controlAAD, plaintext)
// ...
plaintext, seq, err := session.Open(controlAAD, frame)
switch {
case errors.Is(err, spindle.ErrReplay):
    // duplicate or outside the window — drop it, session is still good
case errors.Is(err, spindle.ErrSeqExhausted):
    // tear down and re-handshake
case err != nil:
    // authentication failure — log it, drop the frame
}
```

`Session` is safe for concurrent use.

### Firmware attestation

Both endpoints use the post-message-1 snapshot as the signed transcript — see
[SPEC.md §5.1](SPEC.md) for why it is a snapshot rather than the final binding.

```go
// Device, while composing msg2:
sig := signer.Sign(spindle.AttestationInput(
    d.AttestationBinding(), fwHash, fwVersion, nonce))

// Controller, after Complete:
ok := spindle.VerifyAttestation(
    dev.IdentityPub, sig, c.AttestationBinding(), fwHash, fwVersion, nonce)
```

An absent signing key or signature verifies as **invalid**, never as success.

## Status

The cryptography is stock Noise and unmodified. The composition around it — the
pin check, snapshot-based attestation, and externally-driven nonces — has not
been formally modelled. That is the largest open item and it is stated in the
spec rather than buried.

Version 2 is a flag-day protocol: there is no negotiation with version 1 and no
compatibility mode, because a downgrade path would reintroduce the negotiation
surface the design exists to avoid.

Tests cover both handshake roles, scope and pinning rejection, replay and
out-of-order delivery, forged-frame window behaviour, sequence exhaustion,
attestation tampering, and wordlist completeness.

```
go test -race ./...
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive areas and the
cross-endpoint testing norm are called out there.

To report a vulnerability, see [SECURITY.md](SECURITY.md) — please do not open a
public issue.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Third-party attribution is in [NOTICE](NOTICE); trademark usage is covered by
[TRADEMARKS](TRADEMARKS).
