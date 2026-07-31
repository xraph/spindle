# Spindle Protocol Specification

Version 2 · `spindle/v2` · Noise_IK_25519_ChaChaPoly_BLAKE2b

---

## 1. Purpose

Spindle is an end-to-end secure channel for remote control of physical and
virtual devices across an untrusted message broker.

It exists because transport security does not solve this problem. MQTT, AMQP and
similar pub/sub transports terminate TLS at the broker, so the broker holds
plaintext for every message that passes through it. When those messages actuate
real hardware — a valve, a motor, a breaker — the broker is inside the trust
boundary whether the deployment intended it or not, and "we use TLS" describes a
different guarantee than the one operators believe they have.

Spindle moves confidentiality and authenticity to the two endpoints. A
compromised broker can observe ciphertext, drop frames, reorder them, or replay
them; it cannot read a command, forge one, or alter one.

### 1.1 Scope

In scope: mutual authentication, forward secrecy, per-frame authenticated
encryption, replay rejection under out-of-order delivery, and the commissioning
primitives that bind a device's key to a physical act of provisioning.

Out of scope, and deliberately left to the caller: device registry,
authorization, command semantics, audit storage, and transport framing. Spindle
is a channel, not a control plane.

---

## 2. Threat model

**Trusted:** both endpoints, their long-term key material at rest, and the
out-of-band channel used once during commissioning (an operator physically at
the device).

**Untrusted:** the broker, the network, and every intermediary. The adversary is
assumed to be a full active network attacker who can read, drop, reorder,
duplicate, and inject frames, and who may hold valid broker credentials.

**Guaranteed against that adversary:**

| Property | Mechanism |
|---|---|
| Confidentiality of commands and responses | ChaCha20-Poly1305 under a session key the broker never holds |
| Authenticity and integrity | AEAD tag per frame; Noise mutual authentication |
| Forward secrecy | ephemeral-ephemeral DH; compromise of a static key does not open recorded sessions |
| Peer authentication | static keys pinned in both directions at commissioning |
| Replay rejection | per-frame sequence number and sliding window |
| Cross-scope confusion | deployment scope bound into the Noise prologue |
| Cross-class confusion | per-traffic-class AAD |
| Commissioning MITM | operator-compared fingerprint over the provisioning transcript |

**Not guaranteed:**

- **Availability.** A broker that drops frames denies service. Spindle detects
  it; it cannot prevent it.
- **Traffic analysis resistance.** Frame sizes and timing are visible. A broker
  can infer activity patterns and roughly how large a command was.
- **Compromised-endpoint recovery.** A device whose static private key is
  extracted can be impersonated until that key is revoked out of band.
- **Controller identity-key compromise.** An attacker holding the controller's
  static private key can impersonate the controller to every device pinned to
  it. Recovery is operational: revoke and re-provision. There is no in-band
  recovery, by design — an in-band recovery path is an in-band takeover path.

---

## 3. Cryptographic construction

The channel is **`Noise_IK_25519_ChaChaPoly_BLAKE2b`**, unmodified. The protocol
name is exactly what the implementation negotiates, and a test asserts that the
advertised name matches the suite actually constructed.

| Primitive | Role | Rationale |
|---|---|---|
| X25519 (RFC 7748) | DH for all handshake legs | Constant-time in the Go standard library; no point-validation footgun. P-256 ECDH costs more bytes for no security gain. |
| ChaCha20-Poly1305 (RFC 8439) | Per-frame AEAD | Constant-time in software, which matters on devices without AES-NI. AES-GCM would either require hardware support or be both slower and more side-channel-prone. |
| BLAKE2b (RFC 7693) | Handshake hashing, HKDF, all derived values | Faster than SHA-256, native keyed mode for domain separation. |
| Ed25519 (RFC 8032) | Firmware attestation; audit-log heads | Deterministic nonces, so no ECDSA-style RNG failure mode. **Not used in the handshake** — see §4.2. |

### 3.1 Why a published pattern rather than a bespoke one

Version 1 of this protocol used a hand-written IK-like pattern. It was replaced
because the security properties were never the problem — vouchability was. A
reviewer evaluating a bespoke handshake must audit the transcript construction,
the key schedule, and the state machine before trusting any of it. A reviewer
evaluating `Noise_IK_25519_ChaChaPoly_BLAKE2b` reads one line and moves on to
the parts that are actually specific to this system.

Adopting the standard pattern also removed three hand-rolled constructions that
had no reason to exist: a custom transcript format, a custom key-derivation
step, and a single session key shared across both directions. See §9.

The pattern is fixed. There is no negotiation, no version byte, and no
alternative suite, so there is nothing for an attacker to downgrade to. The cost
is that changing anything in this document is a flag-day migration requiring
every device to be re-provisioned. That cost was accepted deliberately in
preference to carrying a negotiation surface.

---

## 4. Handshake

```
controller → device   msg1:  e, es, s, ss   + encrypted payload
device → controller   msg2:  e, ee, se      + encrypted payload
```

The controller is the Noise **initiator**; the device is the **responder**. This
follows from the deployment: the controller reaches out to a device whose static
public key it already holds from commissioning, which is precisely IK's premise.

Both payloads are encrypted. In msg1 the payload follows `es`, so a key is
already established when it is written — it is a safe place for a challenge
nonce. In msg2 the payload carries device identity and attestation evidence.

### 4.1 Pinning in both directions

IK gives the initiator the responder's static as a pre-message. The controller
therefore pins the device's static public key, recorded at commissioning. A
handshake against an unpinned device is refused before any message is written.

IK does **not** give the responder the initiator's static in advance — it
arrives inside msg1, and the `ss` leg proves the sender holds the matching
private key. That establishes the controller is *authentic*, but not that it is
the *expected* controller. Spindle therefore adds an explicit check: after
reading msg1, the device compares the delivered static against the controller
key written during commissioning, in constant time, and aborts on mismatch.

Without that check a device would complete a handshake with any controller that
knew its public key. This is the one security-relevant addition Spindle makes to
the pattern, and it is a comparison, not a modification of the cryptography.

### 4.2 Deployment scope binding

The deployment scope is bound through the Noise **prologue**, which is hashed
into the handshake state before any key material is mixed:

```
prologue = "spindle/v2" || uint16be(len(scope)) || scope
```

Both endpoints must derive identical prologues or every subsequent MAC check
fails. A device commissioned for one scope cannot be re-pointed at another: the
handshake fails outright rather than producing a working session in the wrong
place. The length prefix prevents adjacent-value collisions — without it, scope
`"ws"` followed by other bytes could hash identically to `"wsx"`.

### 4.3 No signature over the transcript

Version 1 signed the handshake transcript with a separate Ed25519 key. That is
removed. Under IK both peers are authenticated by their static X25519 keys
through the DH pattern itself, so a signature adds no authentication — it only
adds a second key to manage and a second construction to review.

The Ed25519 key is retained for signatures that genuinely sit *above* the
channel: firmware attestation on the device side, audit-log heads on the
controller side. Keeping it distinct from the channel identity means compromise
of one does not imply compromise of the other.

---

## 5. Firmware attestation

A device may prove which firmware it is running, bound to the live handshake so
the proof cannot be reused.

The signed input is:

```
attestation_input = len32(binding)  || binding
                 || len32(fw_hash)  || fw_hash
                 || uint64be(fw_version)
                 || len32(nonce)    || nonce
```

Every variable-length field is length-prefixed. Without prefixes, a firmware
hash of a different length would shift the bytes that follow, and one signature
could be reinterpreted as a signature over different claims.

### 5.1 Why the binding is a snapshot

`binding` is the Noise handshake hash **as it stands immediately after msg1**,
not the final channel binding.

This is forced by the message flow. The device must produce its signature while
composing msg2, at which point it has processed msg1 but has not yet mixed its
own ephemeral. The controller therefore captures the same intermediate state
right after writing msg1. Both sides hold identical bytes covering the prologue,
both static keys, the controller's fresh ephemeral, and the msg1 payload.

That is sufficient for the property that matters: the controller's ephemeral and
the challenge nonce are fresh per session, so an attestation cannot be lifted
from one session into another. It does not cover the device's ephemeral, which
is not needed — the device's identity is already established by the pinned
static.

A device with no provisioned signing key produces no signature. Verification
treats an absent key or signature as **invalid**, never as success; deployments
requiring attestation must provision a signer at commissioning.

---

## 6. Data frames

```
| 8B sessionID | 8B seq | ciphertext || 16B tag |
```

Maximum plaintext per frame is 65519 bytes (Noise's 65535-byte message limit
less the tag). Callers needing more must fragment above this layer.

**The AEAD nonce is not transmitted.** It is the sequence number, which is
already in the header. Sending it separately would add bytes and hand the
attacker a degree of freedom over nonce selection.

**Session identifier.** Derived independently by both endpoints from the
completed channel binding:

```
sessionID = BLAKE2b-64(binding; key="spindle/v2/sid")
```

It never crosses the wire during the handshake, so there is no mismatch case to
check — a peer that derived a different binding could not have produced a valid
frame at all. It is unique per handshake because the binding covers both fresh
ephemerals.

**Traffic-class separation.** Each frame class passes a distinct AAD derived from
a label:

```
aad = BLAKE2b-256(label; key="spindle/v2/aad")
```

A frame sealed for one class cannot be accepted as another, so a captured
heartbeat cannot be replayed into the control path even though both directions
share a session.

### 6.1 Out-of-order delivery and replay

This is the one place where Spindle steps outside the plain Noise transport
model, and the reason this specification exists rather than "just use Noise".

Noise's `CipherState` assumes an ordered stream and advances its nonce
internally. Pub/sub transports provide no ordering. Spindle therefore carries the
sequence number explicitly and drives the receiving cipher state's nonce from the
wire value, gated by a sliding window (default tolerance 64 frames, one word of
bitmap; a tolerance of 0 makes the receiver strictly monotonic).

Three rules make this safe:

1. **A frame that fails authentication never marks its sequence as seen.** The
   window is consulted only after the AEAD check succeeds, so an attacker cannot
   exhaust window slots with forged frames. The cost is that a replayed frame is
   decrypted before being rejected — acceptable, because only a genuinely
   captured frame can reach that point.
2. **Sequence 0 is a valid first frame.** An empty window and a window whose
   highest-accepted value is 0 are distinct states. Conflating them rejects the
   opening frame of every session as a duplicate of itself.
3. **Sequence exhaustion is a hard error, never a wrap.** Reusing a
   `(key, nonce)` pair under ChaCha20-Poly1305 is catastrophic — it leaks the
   keystream and, with Poly1305, the authenticator key. Spindle refuses to send
   past the maximum and requires a fresh handshake.

### 6.2 Rekey

By teardown and re-handshake. There is no rekey message. This keeps the state
machine at two message types and one terminal state; the alternative is a third
message type plus its own counter and replay considerations.

---

## 7. Commissioning

Commissioning binds a device's key to a physical act. The channel cannot
establish first-contact trust on its own — pinning has to start somewhere, and
that somewhere is an operator at the device.

**Fingerprint.** The provisioning transcript is rendered as six words from a
256-entry wordlist (one byte per word, 48 bits), which the operator compares
between the device display and the admin interface. Any substituted key changes
the output, making a mismatch a reliable MITM indicator. Comparison is
constant-time.

The wordlist is 256 short, phonetically distinct English words with no
homophones and no pairs that look alike on a low-quality LCD. All 256 slots must
be populated: a short list silently renders blank words for digest values that
index past its end, weakening exactly the comparison this mechanism exists to
provide. A test enforces completeness and uniqueness.

A BIP39-style encoding would pack more bits per word but adds roughly 10 KB to a
device binary. 48 bits is far above the point where the operator's attention is
the weak link, and commissioning carries additional independent factors.

The fingerprint transcript is the handshake binding and nothing else. Anything
further to be bound belongs inside that transcript: a fingerprint that mixes in a
value only one endpoint knows cannot agree across the two, and an operator told to
compare two strings that can never match learns to ignore the mismatch — which
removes the defence entirely.

**Liveness code.** A separate 6-digit code, generated by the controller, that the
operator relays between the device and the admin interface to demonstrate physical
presence. The controller stores only its hash and destroys the seed once
commissioning completes.

It is an independent factor, deliberately **not** folded into the fingerprint. The
two mechanisms answer different questions — the code asks "is an operator really
at the device?", the fingerprint asks "were any keys substituted?" — and only the
controller ever holds the code, so binding it into a value both endpoints must
compute is not possible.

No password-style KDF is applied to either value. Neither is a secret at rest: the
fingerprint derives from public transcript material, and the code's seed is
destroyed on completion. A KDF would add cost without adding a property.

---

## 8. Residual risks and open work

Stated plainly, because a specification that hides its gaps is not reviewable.

- **No formal model.** The pattern is machine-verified upstream as part of the
  Noise framework, and Spindle does not alter the cryptography. But the
  composition — pin check, snapshot-based attestation, externally-driven nonces
  — has not been formally modelled. This is the largest open item.
- **Externally-driven nonces are a sharp edge.** §6.1 places the responsibility
  for nonce discipline on this layer rather than on Noise. The rules are simple
  and tested, but it is the part of the design most likely to be broken by a
  careless future change, and any modification to the frame path warrants
  disproportionate review.
- **No long-term key rotation protocol.** Rotation is entirely out of band. This
  is intentional, but it means rotation tooling is a caller responsibility.
- **Side channels on exotic hardware.** X25519 and ChaCha20-Poly1305 are
  constant-time in the Go standard library on mainstream targets. Deployments
  concerned about specialised side channels on unusual hardware should pin a
  hardened build.
- **Traffic analysis.** No padding or cover traffic. Frame sizes and timing leak
  activity patterns to the broker.
- **Replay window is one 64-bit word.** Tolerances above 64 frames need a
  different representation. Values above 64 are clamped rather than rejected.

---

## 9. Changes from version 1

Version 2 is a flag-day migration. There is no negotiation between versions and
no compatibility mode — every device re-provisions. Retaining a downgrade path
would have reintroduced the negotiation surface the design exists to avoid.

| Area | Version 1 | Version 2 |
|---|---|---|
| Pattern | hand-written IK-like | stock `Noise_IK_25519_ChaChaPoly_BLAKE2b` |
| Key schedule | `BLAKE2b(dh1‖dh2‖dh3)`, single step | Noise chained `MixKey`/HKDF |
| Session keys | one key both directions, direction tag in the nonce | two keys from `Split()` |
| Server auth | Ed25519 signature over a hand-built transcript | implicit, via the pattern's static DH |
| Scope binding | hand-built transcript field | Noise prologue |
| Pinned controller value | Ed25519 signing key, checked against sealed state | X25519 static, checked against sealed state |
| Session ID | random, transmitted, compared | derived from the channel binding |
| Sequence numbers | caller-managed | session-managed |
| Sequence exhaustion | silent wrap | `ErrSeqExhausted` |
| Attestation input | unprefixed concatenation | every field length-prefixed |
| AEAD instance | constructed per frame | constructed once per session |

Two defects in the version 1 implementation are fixed here and are worth calling
out, because both were silent:

- **Fingerprint wordlist was short — an active defect.** Declared as a 256-entry
  array with 252 entries populated, leaving indices 252–255 as the empty string.
  9.02% of fingerprints rendered with at least one missing word, and those four
  digest values were indistinguishable from one another in the displayed string —
  on the MITM-detection path.
- **Replay window rejected sequence 0 — latent.** An empty window was
  indistinguishable from one whose highest-accepted sequence was 0, so a first
  frame numbered 0 was rejected as a duplicate of itself. Version 1 never
  triggered it because its callers pre-incremented and began at 1; the bug was
  waiting for a caller that did not. Version 2 takes its sequence from the Noise
  cipher state, which starts at 0, so the window had to be corrected rather than
  worked around.

---

## 10. References

- Trevor Perrin, *The Noise Protocol Framework*, revision 34 — the pattern, the
  key schedule, and the `Split()` ordering this specification relies on.
- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
- RFC 7693 — BLAKE2 Cryptographic Hash and MAC
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 7250 — Raw Public Keys in TLS/DTLS, for comparison: the closest standard
  alternative, and one that does not survive an untrusted intermediary.
