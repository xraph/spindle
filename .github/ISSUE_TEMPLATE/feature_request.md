---
name: Feature request
about: Suggest an idea for Spindle
title: '[FEATURE] '
labels: enhancement
assignees: ''

---

## Problem

What are you unable to do today? Describe the situation rather than the solution.

## Proposed solution

What you would like Spindle to do.

## Does this change the wire format?

- [ ] No — API or documentation only
- [ ] Yes — bytes on the wire change
- [ ] Not sure

Spindle has no version negotiation, deliberately: a fixed pattern means there is
nothing to downgrade to. The cost is that any wire change is a flag day requiring
every deployed device to re-provision, so those proposals need a correspondingly
strong justification.

## Alternatives considered

Other approaches you looked at, including doing this in your own code above the
channel.

## Scope check

Spindle is a channel, not a control plane. Device registry, authorization,
command semantics, audit storage, and transport framing are deliberately out of
scope — see SPEC.md §1.1. If your request is one of those, it probably belongs in
the layer above.

## Additional context

Anything else relevant.
