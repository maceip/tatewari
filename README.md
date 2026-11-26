
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

The [second act](#second-act-the-evidence-plane) attacks the record instead of the
traffic: ten scenarios, each a way to be recorded honestly and still name nobody.

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

## Second act: the evidence plane

The four channels above assume the record exists and says the right thing. It is
worth attacking the record instead. Each scenario below is a port of a named line in
shirudo's `upatches/kernel-obs/`, driven by real traffic: a real datagram to a
receiver this process owns, a real DNS query answered by a real resolver, and the
observer's own hash, bucket count, probe limit, port filter, name-slot count and
buffer lifetime.

| Scenario | Verdict | What shirudo's code does | Where |
|---|---|---|---|
| `export_partial` | lost | an export that stops before the last record leaves the drain buffer uncleared; the next pass destroys it and reports `lost` | `obs_table.h:155`, `:379` |
| `export_stall` | refused | past capacity the table refuses the entry, by insertion order | `obs_table.h:127` |
| `attribution_blank` | unattributed | with no socket-storage record the key keeps a cgroup id and `exe` stays zero | `obs_net.bpf.c:965` |
| `unsocketed_packet` | unrecorded | cgroup_skb runs only for a full socket, so a skb without one produces no record | kernel, not the upatch |
| `dns_offport` | unjoined | answers are parsed only from the configured resolver port | `obs_dns.bpf.c:828` |
| `dns_qtype_txt` | unjoined | only A and AAAA are parsed, and the refusal counter is internal, never exported | `obs_dns.bpf.c:642`, `:161` |
| `dns_nxdomain` | unrecorded | a response with no answer returns before anything is stored, so absence carries a bit | `obs_dns.bpf.c:755` |
| `dns_name_launder` | evicted | four name slots per address; the fifth resolution evicts the oldest | `obs_dns.bpf.c:272` |
| `dns_id_confusion` | confused | the pending question is stored with `BPF_ANY`, and both the recorded name and the recorded executable come from it, never from the answer | `obs_dns.bpf.c:663`, `:302` |
| `bucket_collision` | split | the lookup walks at most eight links and inserts at the head, so the ninth key in a bucket is inserted and then unfindable | `obs_table.h:113`, `:138` |

Four of them are worth running in front of an audience, because the evidence file
carries the number that makes the claim true:

- `dns_nxdomain` really transmits. A canary byte goes out as eight real queries; some
  resolve and some do not; the analyst decodes the byte back from *which addresses
  appear in the `dns` table at all*. Nothing written down says what the bit was.
- `bucket_collision` really splits. The carrier port yields two entries of one packet
  and 29 bytes each, while a control port yields one entry of two packets and 58
  bytes. The colliding ports are chosen from the observer's own hash over the whole
  port range, not hoped for.
- `export_partial` really destroys. The datagram's arrival is proven by the receiver,
  the partial export ships one of the two records, and the restart reports `lost: 2`
  and exports nothing. `lost` counts the whole abandoned buffer, including the page
  that did get sent.
- `dns_qtype_txt` really is silent. A TXT answer arrives, the kernel's
  `query_qtype_unsupported` counter increments, and no snapshot contains it.

Two scenarios carry `basis: modelled` and say why in their notes:
`unsocketed_packet` fixes the one property the demo cannot vary on every platform
(whether the skb carries a socket), and `dns_id_confusion` fixes which of two in-flight
queries the observer saw first. The datagrams and DNS packets in both are real. The
resolver port is remapped off 53 so no privileged bind is needed, and the port filter
is still exercised: `dns_offport` points the observer at a port the query did not use.

Two of the ten scenarios also carry `basis: modelled` in the model, and the section
below replaces that basis with records from a real target: `unsocketed_packet` turned out
to behave differently there, and the write-up says so rather than the other way round.

`live/` is an earlier, standalone route to the same question: a small C probe
that attaches the upatch's `cgroup_skb` programs itself and calls the upatch's own
serializer, for a kernel where shirudo is not installed. The results in this repo come
from `vm_runner` against a real shirudo target, not from `live/`.

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

## The same ten scenarios on a real target

`observer_model` is a line-by-line port of `upatches/kernel-obs`, and a port can be
wrong. `vm_runner` therefore runs the same ten scenarios against a real one: shirudo's
own test target (kernel `7.4-shirudo-ci-20261123`, vTPM, `Status: ok`, the `kernel-obs`
upatch loaded and measured), reads the signed upatch's own exported snapshots with
`shirudo upatch map kernel-obs <table> --json`, and judges the same claims from the
records.

```sh
# on the target, with the upatch loaded
PYTHONPATH=/workspace/shirudo python3 -m tatewari.vm_runner
PYTHONPATH=/workspace/shirudo python3 -m tatewari.vm_runner --only dns_id_confusion --json
```

`observed/target-kernel-obs.json` is one such run, kept so the numbers below can be
re-read rather than retaken. Eight of the ten claims hold exactly as the model predicts:

| Scenario | Observed | The number that decides it |
|---|---|---|
| `attribution_blank` | unattributed | the kernel's own ICMP is recorded with `executable.ino` 0 and `pid` 0, while the datagram that caused it keeps both |
| `dns_offport` | unjoined | the datagram to `:5353` is in `net`; no `dns` entry names it |
| `dns_qtype_txt` | unjoined | a TXT answer is counted as bytes; its name never reaches the table |
| `dns_nxdomain` | unrecorded | `0xa7` sent as eight NXDOMAIN questions, `0xa7` decoded from them, no `dns` record for any of them |
| `dns_name_launder` | evicted | five names at one address keep `x2..x5.evil.test`; `v1..v3.probe.test` are gone |
| `dns_id_confusion` | confused | the late answer for `127.0.0.41` is filed under `decoy.probe.test`; the victim's name is recorded nowhere |
| `bucket_collision` | split | the peer's entry moves on the eighth colliding key: `OBS_T_STEPS` is 8, and its totals split into (8 packets, 232 bytes) and (1 packet, 29 bytes) |
| `export_stall` | refused | 1040 peers offered, 1024 recorded, `interval.overflow` 16, the first peer present and the last absent |

Two do not, and the model was wrong in both:

- **`unsocketed_packet` — observed `unattributed`, not `unrecorded`.** A packet with no
  socket behind it is still counted. The kernel's ICMP lands in `net` with an empty
  identity, so the traffic is not invisible; it is unattributable. That is the thesis of
  this whole plane, and the model overstated it.
- **`export_partial` — observed `survived`, not `lost`.** `flip()` does destroy an
  undrained buffer and count it into `lost` (`obs_table.h:155-171`), but shirudo's own
  reader takes the whole interval in one pass, so on this target the path is never taken.
  A full 403-record interval read and re-read reports `lost: 0`. The claim survives as a
  statement about readers that stop early, not about this one.

Two things had to be arranged for the run to be readable at all, and both are worth
knowing before filling a table yourself:

- the target's `shirudo-map-export.timer` was stopped, so each scenario reads the
  interval it wrote instead of having the periodic exporter take it first;
- the capacity test uses the `dns` table (capacity 1024), because a full `net` interval
  (8192 entries) is too large for shirudo's signed Lua decoder: the read stops with
  `decoder instruction limit exceeded` and returns no JSON at all.

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

The evidence plane has its own entry point, which exits non-zero unless every
scenario reaches the verdict its weakness predicts:

```sh
.venv/bin/python -m tatewari.evidence_pipeline --list
.venv/bin/python -m tatewari.evidence_pipeline
.venv/bin/python -m tatewari.evidence_pipeline --only dns_nxdomain,bucket_collision
.venv/bin/python -m tatewari.evidence_pipeline --family name_join --json
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
