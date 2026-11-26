# Contributing

## Setup

Requires Python 3.11–3.14 and the [spar](https://github.com/maceip/spar) checkout
on branch `feat/shirudo-egress-evasion`, next to this repo:

```sh
git clone https://github.com/maceip/spar ../spar
git -C ../spar checkout feat/shirudo-egress-evasion
python3.12 -m venv .venv
.venv/bin/pip install -e ../spar -e ".[dev]"
```

## Checks

Both must pass before a change is proposed:

```sh
.venv/bin/ruff check tatewari tests live observed
.venv/bin/ruff format --check tatewari tests live observed
.venv/bin/python -m pytest
```

The egress and evidence-plane tests drive real loopback traffic (UDP receivers,
a resolver this process owns); they need no privileges and no network beyond
localhost. The observed-fixture tests read `observed/target-kernel-obs.json`
offline. `vm_runner` and `live/` only run on a target with the kernel-obs upatch
loaded; CI does not run them.

## Rules

- **One implementation.** The egress capability imports its implementation from
  spar; do not copy or reimplement it here. `observer_model.py` is a port of
  named lines in shirudo's `upatches/kernel-obs/`; where the port and that code
  disagree, that code is right, and the divergence is written up, not patched
  away.
- **Verdict honesty.** A verdict needs both halves: arrival proven at a sink the
  process owns, and detector silence recomputed from exported records. Silence
  from a broken or silent observer is inconclusive, never evasion. Keep the
  positive controls.
- **Public messaging.** The README's opening stays aligned with the
  four-quiet-ways-out post: DNS / Ports / Timing / HTTP, recorded but not
  interpreted. This is a demonstration against a model and a test target, not
  an attack on a live deployment.
- **Licensing.** Contributions are under the BSD-2-Clause license. Every new
  source file starts with an SPDX identifier (see existing files).

## AI contributions

You may use AI tools, but you are expected to take personal responsibility for
the content, as if you authored it without them.
