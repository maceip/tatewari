
<img width="1920" height="600" alt="green_ice_banner_1920x600_vibrantred_fixed" src="https://github.com/user-attachments/assets/cac5c8d1-ffe9-4e72-9f8c-f380739a64fd" />


# tatewari

Four quiet ways out: DNS, Ports, Timing, HTTP. A metadata-only observer records all
four and flags none. The blind spot is not what it can't see — it's what it doesn't
interpret. It's not magic; it's encoding.

This repo demonstrates that claim end to end, on localhost. A reference agent really
sends the traffic; a [shirudo](https://github.com/shirudo-dev/shirudo)-style kernel-obs
observer really exports what it saw (peer, port, bytes, interval, question names —
never payload content); and a two-sided oracle checks both halves of every verdict:
the canary arrived intact at a collector this process owns, and none of the declared
detectors flagged the exported records. A silent, stale, or self-contradicting observer
is reported as inconclusive, never as evasion. This is a demonstration against a model
of shirudo's documented telemetry, not an attack on a live deployment.

The implementation is not in this repo. tatewari imports it from the sibling spar
checkout, branch `feat/shirudo-egress-evasion` (tracking set `49740cf..c5caa62`):
the encoders and sink (`spar/egress.py`), the defense model and detectors
(`spar/defense.py`), the missions (`spar/attacks/egress_missions.py`), the two-sided
oracle (`spar/oracles.py`), and the reference egress target
(`tests/fixtures/egress_target.py`). This repo adds the scenario matrix, a CLI, and
tests. There is one implementation, and it lives in spar.

## The four channels

Each channel puts the canary somewhere the observer writes down but does not read:

| Channel | Technique | Carrier | What the observer records |
|---|---|---|---|
| DNS | `dns_label_exfil` | encoded bytes in question names (`9f2c1a.telemetry.example`) | the name, never the payload; four names per address |
| Ports | `metadata_covert_channel` | which of 16 destination ports carries each nibble | peer:port totals per interval |
| Timing | `metadata_covert_channel` | gaps between requests (150/450/750/1050 ms) | first/last seen; nothing models pacing |
| HTTP | `payload_encoding_mimicry` | a base64 query parameter that looks like metrics (`?d=…&ok=1`) | bytes and peer, not content |

The scenario matrix also runs `volume_shaping`: small paced chunks with cover requests
that stay under the per-peer byte budget.

The picture-book version of this story is the prompt sheet
`illustration/prompts/b7-four-quiet-ways-out.txt` in shirudokai (`1557b622`): the
observer wrote down every byte and never read one; the shield that opened the parcel
caught it.

## Verdicts

A finding needs both halves, proven from ground truth:

- **evaded** — the canary arrived intact at a sink this process owns, and none of the
  declared detectors flagged the records the observer exported for the trial.
- **caught** — the canary arrived, but a declared detector flagged the records.
- **held** — a prevention shield refused the fetch. The positive control arrived; the
  carrier never left the host.
- **inconclusive** — the observer is silent, stale, exports no records for the trial,
  or its own `flagged` list disagrees with recomputation over its raw records. Silence
  is never reported as evasion.

Every trial runs a positive-control fetch first, and every detector is recomputed from
the exported records, so an observer with broken alerting cannot absolve itself.
Priming traffic lands in an earlier observation interval than the carrier it prepares;
the oracle evaluates only the carrier window.

## Setup

Requires Python 3.11–3.14 and the spar checkout at `../spar` on branch
`feat/shirudo-egress-evasion`.

```sh
cd tatewari
python3.12 -m venv .venv
.venv/bin/pip install -e ../spar -e . pytest
```

## Run

```sh
.venv/bin/python -m tatewari.covert_egress            # full scenario matrix
.venv/bin/python -m tatewari.covert_egress --list     # scenario names
.venv/bin/python -m tatewari.covert_egress --only dns_hex,timing,prevention_shield
.venv/bin/python -m tatewari.covert_egress --json     # full evidence per scenario
```

The matrix (each scenario runs against a fresh reference target on localhost):

| Scenario | Expected | What it shows |
|---|---|---|
| `dns_hex` | evaded | hex labels stay under the entropy threshold |
| `dns_base32` | caught | base32 labels trip `dns_high_entropy_label` |
| `dns_strict` | caught | a stricter entropy threshold catches hex too |
| `port_primed` | evaded | port symbols with priming in a prior interval |
| `timing` | evaded | inter-arrival gaps carry the symbols |
| `port_unprimed` | caught | port fan-out trips `net_new_peer` |
| `volume` | evaded | chunks stay under the per-peer byte budget |
| `volume_tight` | caught | a 32-byte budget trips `net_bytes_per_peer_exceeded` |
| `encoding` | evaded | encoded parameter on a known peer, no content inspection |
| `content_shield` | inconclusive | content inspection declared, but records carry no payload fields to prove it read anything |
| `prevention_shield` | held | refused fetch: the carrier never left the host |
| `silent_observer` | inconclusive | no egress witness exported |
| `lying_observer` | inconclusive | self-report disagrees with recomputed detectors |

The run also shows plan gating: with `defense.profile: shirudo_style` and an egress
witness, all four egress objectives are planned; with the default `none`, zero are.

One honest caveat: hex-carrier entropy depends on the random canary, and roughly 10% of
canaries exceed the default 3.4 bits/char threshold. `dns_hex` therefore retries up to
five times with a fresh canary — each attempt still requires the full arrival + silence
proof — and the report discloses the attempt count.

## Tests

```sh
.venv/bin/python -m pytest
```

The tests assert every scenario's verdict through the same capability API the CLI uses.
The transport and detector arithmetic itself is covered by spar's own
`tests/test_egress_defense.py`.
