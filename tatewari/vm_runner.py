# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of tatewari
"""The evidence plane, observed: the same ten scenarios against a real target.

``evidence_pipeline`` asks a Python model of ``upatches/kernel-obs`` what
shirudo would write down. This module asks shirudo itself. It runs the same
traffic -- real UDP sockets, real DNS packets, receivers and a resolver this
process owns -- and then reads the signed upatch's own exported snapshots
(``shirudo upatch map kernel-obs <table> --json``) and judges the same claims
against what the kernel actually recorded.

Two rules carry over unchanged, because they are about honesty and not about
which side of the boundary judges:

  * a scenario that claims a record is missing must show the same pipeline
    recording its control in the same interval, or the verdict is
    ``inconclusive``;
  * nothing is inferred that the snapshot does not contain. The model's
    verdicts are the expectation; the observed verdict is whatever the
    records say, including ``survived`` when the weakness does not show.

Run it on a target with the kernel-obs upatch loaded, as root::

    PYTHONPATH=/workspace/shirudo python3 -m tatewari.vm_runner --only dns_offport

Every finding carries the raw snapshot it was judged from under
``evidence``, so a disputed verdict can be re-read without rerunning.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import socket
import subprocess
import sys
import time

from .evidence_pipeline import (
    Finding,
    Resolver,
    UdpSink,
    query_once,
    send_udp,
)
from .observer_model import (
    DNS_TYPE_A,
    NET_BUCKETS,
    NET_CAPACITY,
    Exe,
    Ident,
    hash_words,
    ipv4_addr_words,
    net_key_words,
)

# The trusted binary on a target: the LSM gives state access to a task that
# executed this path from the runtime image, and to nothing else.
SHIRUDO = "/run/shirudo/runtime/usr/bin/shirudo"
FIXTURE_UPATCH = "/mnt/shirudo-bundle/fixtures/kernel-obs.upatch"
UPATCH = "kernel-obs"


# --------------------------------------------------------------------------
# Talking to the target.


class Target:
    """A host where the kernel-obs upatch is loaded, read through shirudo."""

    def __init__(self, shirudo: str = SHIRUDO) -> None:
        self.shirudo = shirudo
        self.loads = 0

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.shirudo, *args], capture_output=True, text=True, timeout=120
        )

    def ensure_loaded(self) -> str:
        out = self._run("upatch", "list")
        if UPATCH in out.stdout and "yes" in out.stdout:
            return out.stdout
        loaded = self._run("upatch", "load", FIXTURE_UPATCH)
        self.loads += 1
        if loaded.returncode != 0 and "already" not in loaded.stderr.lower():
            raise RuntimeError(f"upatch load failed: {loaded.stderr.strip()}")
        return self._run("upatch", "list").stdout

    def snapshot(self, table: str, *, peek: bool = False) -> dict:
        args = ["upatch", "map", UPATCH, table, "--json"]
        if peek:
            args.append("--peek")
        else:
            args.append("--show-full")
        out = self._run(*args)
        text = out.stdout
        start = text.find("{")
        if start < 0:
            raise RuntimeError(
                f"{table}: no JSON in output (rc={out.returncode}): "
                f"{out.stderr.strip()[:300]}"
            )
        return json.loads(text[start:])

    def snapshot_capped(self, table: str = "net", *, peek: bool = False) -> dict:
        """Read without --show-full, as the shipped reader does by default."""
        args = ["upatch", "map", UPATCH, table, "--json"]
        if peek:
            args.append("--peek")
        out = self._run(*args)
        start = out.stdout.find("{")
        if start < 0:
            raise RuntimeError(
                f"{table}: no JSON in output: {out.stderr.strip()[:300]}"
            )
        return json.loads(out.stdout[start:])

    def drain(self, *tables: str) -> dict:
        return {t: self.snapshot(t) for t in tables or ("net", "dns")}


def target_facts(target: Target) -> dict:
    """What this host was, so a saved result can be read again later."""
    import os

    facts = {"kernel": os.uname().release, "upatch_loads": target.loads}
    version = target._run("version")
    for line in version.stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            facts[key.strip().lower().replace(" ", "_")] = value.strip()
    status = target._run("status", "--json")
    start = status.stdout.find("{")
    if start >= 0:
        try:
            doc = json.loads(status.stdout[start:])
        except ValueError:
            doc = {}
        for key in ("verdict", "status", "version_id", "conditions"):
            if key in doc:
                facts[f"status_{key}"] = doc[key]
    return facts


def _records(snapshot: dict) -> list[dict]:
    return list(snapshot.get("records") or [])


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _net_by_peer(
    snapshot: dict, *, addr: str, port: int | None = None, proto: str = "udp"
) -> list[dict]:
    hits = []
    for record in _records(snapshot):
        if record.get("address") != addr:
            continue
        if record.get("proto") != proto:
            continue
        if port is not None and _int(record.get("port")) != port:
            continue
        hits.append(record)
    return hits


def _dns_by_address(snapshot: dict, addr: str) -> list[dict]:
    return [r for r in _records(snapshot) if r.get("address") == addr]


def _dns_names(record: dict) -> list[str]:
    return [n.get("name", "") for n in record.get("names") or []]


def _has_name(snapshot: dict, name: str) -> list[dict]:
    return [r for r in _records(snapshot) if name in _dns_names(r)]


def _ident(record: dict) -> dict:
    exe = record.get("executable") or {}
    return {
        "ino": exe.get("ino"),
        "dev": exe.get("dev"),
        "cgroup": record.get("cgroup_id"),
        "pid": record.get("pid"),
    }


# --------------------------------------------------------------------------
# Controls. No scenario may call an absence a finding without one.


def observed_control(
    target: Target, *, payload: bytes = b"control", peek: bool = False
) -> tuple[bool, dict]:
    """A benign datagram in the interval the scenario is about to judge.

    ``peek`` reads the interval without taking it, so a scenario that needs the
    same interval twice -- to seed a table and then to watch it -- can read its
    own control and its own seed without destroying either.
    """
    sink = UdpSink()
    try:
        facts = send_udp(sink.port, payload)
        arrived = sink.wait(1) >= 1
    finally:
        sink.close()
    time.sleep(0.15)
    snapshot = target.snapshot("net", peek=peek)
    hits = _net_by_peer(snapshot, addr="127.0.0.1", port=facts["dport"])
    recorded = bool(hits)
    return (arrived and recorded), {
        "arrived": arrived,
        "recorded": recorded,
        "port": facts["dport"],
        "control_record": hits[0] if hits else None,
        "interval": snapshot.get("interval"),
    }


def _closed_port() -> int:
    """A UDP port nothing is bound to, so the kernel answers with ICMP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --------------------------------------------------------------------------
# Identity: who the kernel can name.


def scn_attribution_blank(target: Target) -> Finding:
    """A datagram to a closed port draws an ICMP the kernel generates itself."""
    target.drain("net")
    control_ok, control = observed_control(target)
    dead = _closed_port()
    for _ in range(3):
        send_udp(dead, b"nobody-home")
    time.sleep(0.3)
    net = target.snapshot("net")
    icmp = [
        r
        for r in _records(net)
        if r.get("proto") == "icmp" and r.get("address") == "127.0.0.1"
    ]
    blank = [
        r
        for r in icmp
        if _int((r.get("executable") or {}).get("ino")) == 0 and _int(r.get("pid")) == 0
    ]
    udp = _net_by_peer(net, addr="127.0.0.1", port=dead)
    if not control_ok:
        verdict = "inconclusive"
    elif blank:
        verdict = "unattributed"
    elif icmp:
        verdict = "survived"
    else:
        verdict = "unrecorded"
    return Finding(
        name="attribution_blank",
        family="identity",
        expected="unattributed",
        verdict=verdict,
        basis="observed",
        claim="a packet the kernel sends on its own is recorded with no process "
        "to name, while the datagram that caused it is named",
        evidence={
            "control": control,
            "dead_port": dead,
            "icmp_records": icmp,
            "blank_records": blank,
            "udp_records": udp,
            "interval": net.get("interval"),
        },
        notes=[
            (
                "obs_net.bpf.c:965: identity comes from skb->sk and its sk_storage; "
                "a packet the kernel generates has neither"
            ),
            (
                "the ICMP is the same packet class as the modelled unsocketed case, "
                "observed rather than modelled"
            ),
            (
                "the controlling datagram keeps its executable and pid in the same "
                "interval, so attribution works and this record lacks it"
            ),
        ],
    )


def scn_unsocketed_packet(target: Target) -> Finding:
    """Is a packet with no socket recorded at all? The model said no."""
    target.drain("net")
    control_ok, control = observed_control(target)
    dead = _closed_port()
    for _ in range(3):
        send_udp(dead, b"unsocketed")
    time.sleep(0.3)
    net = target.snapshot("net")
    icmp = [
        r
        for r in _records(net)
        if r.get("proto") == "icmp" and r.get("address") == "127.0.0.1"
    ]
    if not control_ok:
        verdict = "inconclusive"
    elif icmp:
        # The record exists, so "no record at all" is not what happens here.
        verdict = "unattributed"
    else:
        verdict = "unrecorded"
    return Finding(
        name="unsocketed_packet",
        family="identity",
        expected="unrecorded",
        verdict=verdict,
        basis="observed",
        claim="a packet with no socket behind it produces no record at all",
        evidence={
            "control": control,
            "dead_port": dead,
            "icmp_records": icmp,
            "interval": net.get("interval"),
        },
        notes=[
            "obs_net.bpf.c:965: sk = skb->sk, and cgroup_skb runs for a socket",
            (
                "observed: the kernel's own ICMP is counted, with an empty identity, "
                "so the traffic is not invisible -- it is unattributable"
            ),
            (
                "this scenario and attribution_blank share one packet class and ask "
                "different questions of it"
            ),
        ],
    )


# --------------------------------------------------------------------------
# Name join: which name gets attached to which bytes.


def _resolver_snapshot(
    target: Target, *, mode: str, port: int, answer: str, name: str
) -> tuple[dict, dict, object]:
    resolver = Resolver(mode=mode, answer=answer, port=port)
    try:
        facts = query_once(resolver.port, name, DNS_TYPE_A)
        resolver.wait(1)
        time.sleep(0.25)
        dns = target.snapshot("dns")
        net = target.snapshot("net")
    finally:
        resolver.close()
    return facts, {"dns": dns, "net": net}, dns


def scn_dns_offport(target: Target) -> Finding:
    """DNS on a port other than 53: the bytes are recorded, the name is not."""
    target.drain("net", "dns")
    control_ok, control = observed_control(target)
    answer = "127.0.0.31"
    facts, snaps, dns = _resolver_snapshot(
        target, mode="a", port=5353, answer=answer, name="offport.probe.test"
    )
    joined = _has_name(dns, "offport.probe.test")
    net_hits = _net_by_peer(snaps["net"], addr="127.0.0.1", port=5353)
    if not control_ok:
        verdict = "inconclusive"
    elif net_hits and not joined:
        verdict = "unjoined"
    elif joined:
        verdict = "survived"
    else:
        verdict = "inconclusive"
    return Finding(
        name="dns_offport",
        family="name_join",
        expected="unjoined",
        verdict=verdict,
        basis="observed",
        claim="a resolver that is not on port 53 has its bytes recorded and its "
        "names never learned",
        evidence={
            "control": control,
            "query": facts,
            "net_to_resolver": net_hits,
            "dns_snapshot": dns,
            "interval": dns.get("interval"),
        },
        notes=[
            "obs_dns.bpf.c: the parser reads a query only on a fixed port check",
            (
                "net records the datagram in both directions, so the traffic is "
                "visible; the name join is what is missing"
            ),
        ],
    )


def scn_dns_qtype_txt(target: Target) -> Finding:
    """A TXT answer is recorded as bytes, never as a name."""
    target.drain("net", "dns")
    control_ok, control = observed_control(target)
    answer = "127.0.0.32"
    facts, snaps, dns = _resolver_snapshot(
        target, mode="txt", port=53, answer=answer, name="txt.probe.test"
    )
    joined = _has_name(dns, "txt.probe.test")
    net_hits = _net_by_peer(snaps["net"], addr="127.0.0.1", port=53)
    if not control_ok:
        verdict = "inconclusive"
    elif net_hits and not joined:
        verdict = "unjoined"
    elif joined:
        verdict = "survived"
    else:
        verdict = "inconclusive"
    return Finding(
        name="dns_qtype_txt",
        family="name_join",
        expected="unjoined",
        verdict=verdict,
        basis="observed",
        claim="only A and AAAA answers reach the name table; a TXT answer's "
        "query is spent and not exported",
        evidence={
            "control": control,
            "query": facts,
            "net_to_resolver": net_hits,
            "dns_snapshot": dns,
            "interval": dns.get("interval"),
        },
        notes=[
            "obs_dns.bpf.c:642: only A and AAAA records are parsed",
            (
                "the query itself is well formed and answered, so the absence is the "
                "parser's, not the network's"
            ),
        ],
    )


def scn_dns_nxdomain(target: Target) -> Finding:
    """A byte carried by which names are asked, none of which is recorded."""
    target.drain("net", "dns")
    control_ok, control = observed_control(target)
    payload = 0xA7
    names = [f"b{(payload >> (7 - i)) & 1}.y.probe.test" for i in range(8)]
    resolver = Resolver(mode="nxdomain", port=53)
    try:
        for name in names:
            query_once(resolver.port, name, DNS_TYPE_A)
        resolver.wait(len(names))
        time.sleep(0.25)
        dns = target.snapshot("dns")
        net = target.snapshot("net")
    finally:
        resolver.close()
    asked = [entry["qname"] for entry in resolver.served]
    decoded = 0
    for bits in asked:
        label = bits.split(".")[0]
        if label.startswith("b"):
            decoded = (decoded << 1) | int(label[1:] or 0)
    joined = [n for n in names if _has_name(dns, n)]
    net_hits = _net_by_peer(net, addr="127.0.0.1", port=53)
    if not control_ok:
        verdict = "inconclusive"
    elif net_hits and not joined:
        verdict = "unrecorded"
    elif joined:
        verdict = "survived"
    else:
        verdict = "inconclusive"
    return Finding(
        name="dns_nxdomain",
        family="name_join",
        expected="unrecorded",
        verdict=verdict,
        basis="observed",
        claim="a byte can be sent through names that resolve to nothing: the "
        "queries are recorded as packets, their names never as names",
        evidence={
            "control": control,
            "payload_byte": payload,
            "asked": asked,
            "decoded": decoded,
            "net_to_resolver": net_hits,
            "dns_snapshot": dns,
            "interval": dns.get("interval"),
        },
        notes=[
            "obs_dns.bpf.c:755: an answer with ancount 0 returns before storing",
            (
                "the decoder reads only names it asked for itself, so the channel "
                "needs no record to work; the record is what is missing"
            ),
            f"payload sent {payload:#04x}, payload decoded {decoded:#04x}",
        ],
    )


def scn_dns_name_launder(target: Target) -> Finding:
    """Five names at one address, four slots: the fifth decides who is dropped."""
    target.drain("net", "dns")
    control_ok, control = observed_control(target)
    answer = "127.0.0.33"
    resolver = Resolver(mode="a", answer=answer, port=53)
    victim = ["v1.probe.test", "v2.probe.test", "v3.probe.test"]
    launder = [
        "x1.evil.test",
        "x2.evil.test",
        "x3.evil.test",
        "x4.evil.test",
        "x5.evil.test",
    ]
    try:
        for name in victim + launder:
            query_once(resolver.port, name, DNS_TYPE_A)
        resolver.wait(len(victim) + len(launder))
        time.sleep(0.25)
        dns = target.snapshot("dns")
    finally:
        resolver.close()
    records = _dns_by_address(dns, answer)
    kept = _dns_names(records[0]) if records else []
    evicted = [n for n in victim if n not in kept]
    if not control_ok or not records:
        verdict = "inconclusive"
    elif evicted:
        verdict = "evicted"
    else:
        verdict = "survived"
    return Finding(
        name="dns_name_launder",
        family="name_join",
        expected="evicted",
        verdict=verdict,
        basis="observed",
        claim="whoever resolves five names at an address decides which four the "
        "record keeps, and their names can push out the ones you care about",
        evidence={
            "control": control,
            "answer": answer,
            "victim": victim,
            "launder": launder,
            "kept": kept,
            "evicted": evicted,
            "dns_snapshot": dns,
            "interval": dns.get("interval"),
        },
        notes=[
            "obs_dns.bpf.c:14: DNS_MAX_NAMES_PER_IP is 4",
            "obs_dns.bpf.c:272-300: a fifth name evicts the oldest slot",
            f"{len(victim)} names first, then {len(launder)}; kept {len(kept)}",
        ],
    )


def scn_dns_id_confusion(target: Target) -> Finding:
    """Two questions from one socket, one transaction id, answers out of order.

    The victim's answer is held back, the decoy's is sent at once, and the
    victim's is released afterwards. Each name is answered with its own address,
    so which name the record attaches to which address is the only thing this
    measures.
    """
    target.drain("net", "dns")
    control_ok, control = observed_control(target, peek=True)
    victim, victim_addr = "victim.probe.test", "127.0.0.41"
    decoy, decoy_addr = "decoy.probe.test", "127.0.0.42"

    class Reordering(Resolver):
        """Holds the victim's answer, answers the decoy, then releases it."""

        def __init__(self) -> None:
            self.held: tuple | None = None
            self.released = False
            super().__init__(mode="a", port=53)

        def _answer(self, query, qid, qname, qtype, peer):
            if qname == victim and not self.released and self.held is None:
                self.held = (query, qid, qname, qtype, peer)
                return None
            self.answer = decoy_addr
            reply = super()._answer(query, qid, qname, qtype, peer)
            if self.held is not None and not self.released:
                self.released = True
                held_query, held_id, held_name, held_type, held_peer = self.held
                self.answer = victim_addr
                late = super()._answer(
                    held_query, held_id, held_name, held_type, held_peer
                )
                if late is not None:
                    with contextlib.suppress(OSError):
                        self._sock.sendto(late, held_peer)
            return reply

    resolver = Reordering()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        sock.bind(("127.0.0.1", 0))
        query_once(
            resolver.port, victim, DNS_TYPE_A, qid=0x4242, sock=sock, expect_reply=False
        )
        time.sleep(0.25)
        query_once(resolver.port, decoy, DNS_TYPE_A, qid=0x4242, sock=sock)
        time.sleep(0.5)
        sock.close()
        time.sleep(0.2)
        dns = target.snapshot("dns")
    finally:
        resolver.close()

    victim_records = _dns_by_address(dns, victim_addr)
    decoy_records = _dns_by_address(dns, decoy_addr)
    victim_names = [n for r in victim_records for n in _dns_names(r)]
    decoy_names = [n for r in decoy_records for n in _dns_names(r)]
    misfiled = decoy in victim_names and victim not in victim_names
    if not control_ok or (not victim_records and not decoy_records):
        verdict = "inconclusive"
    elif misfiled:
        verdict = "confused"
    else:
        verdict = "survived"
    return Finding(
        name="dns_id_confusion",
        family="name_join",
        expected="confused",
        verdict=verdict,
        basis="observed",
        claim="two questions sharing a transaction id leave the table unable to "
        "say which name an answer belonged to",
        evidence={
            "control": control,
            "victim": victim,
            "victim_addr": victim_addr,
            "decoy": decoy,
            "decoy_addr": decoy_addr,
            "victim_names": victim_names,
            "decoy_names": decoy_names,
            "misfiled": misfiled,
            "dns_snapshot": dns,
            "interval": dns.get("interval"),
        },
        notes=[
            (
                "obs_dns.bpf.c:663: the pending question is stored with BPF_ANY, so a "
                "second question from the same socket overwrites the first"
            ),
            (
                "obs_dns.bpf.c:302-345: the record takes the name from the pending "
                "query and the address from the answer it is writing"
            ),
            (
                "both questions leave one socket with one transaction id, and each "
                "name is answered with its own address, so the join is all that is "
                "being measured"
            ),
        ],
    )


# --------------------------------------------------------------------------
# Table structure: how the entries are made.


def bucket_of(record: dict, port: int, addr: str = "127.0.0.1") -> int:
    """The table bucket a peer lands in, from the record the kernel wrote."""
    exe = record.get("executable") or {}
    ident = Ident(
        exe=Exe(ino=_int(exe.get("ino")), dev=_int(exe.get("dev"))),
        cgroup=_int(record.get("cgroup_id")),
    )
    proto = 17 if record.get("proto") == "udp" else 6
    # obs_common.h:110-114: NONE 0, INITIATOR 1, ACCEPTOR 2, LISTENER 3. A
    # datagram record carries no role field, which is the NONE value.
    role = {"initiator": 1, "acceptor": 2, "listener": 3}.get(
        record.get("role") or "none", 0
    )
    words = net_key_words(ident, 2, proto, role, port, ipv4_addr_words(addr))
    return hash_words(words) & (NET_BUCKETS - 1)


def scn_bucket_collision(target: Target) -> Finding:
    """Fill a peer's probe chain and watch the key move to a second entry.

    Every read here is a peek: the seed, the fillers and the touches have to
    land in one interval, because a record is a per-interval delta and the
    split is only visible while both of the peer's entries are.

    How deep the walk goes is not assumed: colliding keys are added one at a
    time and the peer is touched after each, until the record's entry_index
    changes. That index is the kernel's own statement that the key is now held
    somewhere else, so the count of fillers it took is observed too.
    """
    target.drain("net")
    control_ok, control = observed_control(target, peek=True)
    probe = _closed_port()
    send_udp(probe, b"a")
    time.sleep(0.2)
    net = target.snapshot("net", peek=True)
    seed = _net_by_peer(net, addr="127.0.0.1", port=probe)
    if not seed:
        return Finding(
            name="bucket_collision",
            family="table",
            expected="split",
            verdict="inconclusive",
            basis="observed",
            claim="one peer split into two entries by the probe limit",
            evidence={"control": control, "probe_port": probe},
            notes=["the first touch of the peer was not recorded"],
        )
    bucket = bucket_of(seed[0], probe)
    seed_index = seed[0].get("entry_index")
    # Nine keys have to share one bucket: the peer plus eight. The bucket holds
    # only about eight of the ports in the whole ephemeral range, so the key
    # space here is address as well as port -- every 127/8 address is local and
    # nothing has to listen on it for the table to hold the peer.
    candidates: list[tuple[str, int]] = []
    for host in ("127.0.0.1", "127.0.1.1", "127.0.1.2", "127.0.1.3"):
        for port in range(1024, 65536):
            if host == "127.0.0.1" and port == probe:
                continue
            if bucket_of(seed[0], port, host) == bucket:
                candidates.append((host, port))
        if len(candidates) >= 16:
            break
    del candidates[16:]

    used: list[list] = []
    entries: list[dict] = []
    split_at: int | None = None
    for fhost, fport in candidates:
        send_udp(fport, b"f", host=fhost)
        used.append([fhost, fport])
        send_udp(probe, b"t")
        time.sleep(0.12)
        net = target.snapshot("net", peek=True)
        entries = _net_by_peer(net, addr="127.0.0.1", port=probe)
        if len(entries) > 1 or any(r.get("entry_index") != seed_index for r in entries):
            split_at = len(used)
            break

    totals = [
        (r.get("tx_packets"), r.get("tx_bytes"), r.get("entry_index")) for r in entries
    ]
    if not control_ok:
        verdict = "inconclusive"
    elif split_at is not None:
        verdict = "split"
    elif not entries:
        verdict = "inconclusive"
    else:
        verdict = "survived"
    return Finding(
        name="bucket_collision",
        family="table",
        expected="split",
        verdict=verdict,
        basis="observed",
        claim="one peer becomes two entries once its probe chain is full, and "
        "its totals are severed between them",
        evidence={
            "control": control,
            "probe_port": probe,
            "bucket": bucket,
            "fillers": used,
            "fillers_to_split": split_at,
            "seed_entry_index": seed_index,
            "entries": entries,
            "totals": totals,
            "interval": net.get("interval"),
        },
        notes=[
            "obs_net.bpf.c:153: OBS_T_STEPS bounds the probe chain the walk takes",
            (
                "obs_table.h:114-135: a key the walk does not reach is inserted as a "
                "new entry at the head of the bucket rather than found"
            ),
            (
                "the bucket is computed from the record the kernel wrote, so a split "
                "also confirms the key layout and the hash match the kernel's"
            ),
            (
                "the model's version of this scenario assumed the walk stops one "
                "entry short of what the kernel does; here it is measured instead"
            ),
        ],
    )


DNS_CAPACITY = 1024  # obs_dns.bpf.c:167, OBS_T_CAPACITY for the dns table


def _address_for(index: int) -> str:
    """A distinct loopback address per index; nothing has to be bound to it."""
    return f"127.1.{(index >> 8) & 0xFF}.{index & 0xFF}"


class _PerNameResolver(Resolver):
    """Answers ``p<i>.probe.test`` with the address ``_address_for(i)``."""

    def _answer(self, query, qid, qname, qtype, peer):
        label = qname.split(".")[0]
        index = int(label[1:]) if label[1:].isdigit() else 0
        saved = self.answer
        self.answer = _address_for(index)
        try:
            return super()._answer(query, qid, qname, qtype, peer)
        finally:
            self.answer = saved


def scn_export_stall(target: Target) -> Finding:
    """Offer the dns table more peers than it has slots and see who is refused.

    The dns table holds one entry per answered address, capacity 1024, so the
    fill needs no sockets and no ICMP: the resolver answers each name with an
    address of its own. This table and not `net` because a full `net` interval
    is too large for shirudo's signed Lua decoder, which stops the read with an
    instruction-limit error -- itself worth knowing before you fill a table.
    """
    target.drain("dns")
    control_ok, control = observed_control(target, peek=True)
    offered = DNS_CAPACITY + 16
    resolver = _PerNameResolver(mode="a", port=53)
    try:
        for index in range(offered):
            query_once(resolver.port, f"p{index}.probe.test", DNS_TYPE_A)
        resolver.wait(offered, timeout=10)
        time.sleep(0.4)
        dns = target.snapshot("dns")
    finally:
        resolver.close()
    interval = dns.get("interval") or {}
    refused = _int(interval.get("overflow"))
    has_first = bool(_dns_by_address(dns, _address_for(0)))
    has_last = bool(_dns_by_address(dns, _address_for(offered - 1)))
    recorded = len(_records(dns))
    if not control_ok:
        verdict = "inconclusive"
    elif refused > 0 and has_first and not has_last:
        verdict = "refused"
    elif has_last:
        verdict = "survived"
    else:
        verdict = "inconclusive"
    return Finding(
        name="export_stall",
        family="export",
        expected="refused",
        verdict=verdict,
        basis="observed",
        claim="at capacity the table refuses new peers, so what is kept depends "
        "on arrival order and not on what the peer is",
        evidence={
            "control": control,
            "offered": offered,
            "recorded": recorded,
            "first_address": _address_for(0),
            "last_address": _address_for(offered - 1),
            "first_recorded": has_first,
            "last_recorded": has_last,
            "overflow": refused,
            "interval": interval,
        },
        notes=[
            (
                "obs_dns.bpf.c:167: the dns table is OBS_T_CAPACITY 1024, "
                "OBS_T_BUCKETS 512, OBS_T_STEPS 8"
            ),
            (
                "obs_table.h:130-136: an exhausted table refuses the entry and counts "
                "it in interval.overflow"
            ),
            "the control is recorded in the same snapshot as the refused peer",
            (
                "the net table cannot show this: decoder limits stopped the read at "
                f"{NET_CAPACITY} records, the dns table at {DNS_CAPACITY} does not"
            ),
        ],
    )


def scn_export_partial(target: Target) -> Finding:
    """Read without --show-full: what the shipped cap does to a full interval."""
    target.drain("net")
    control_ok, control = observed_control(target)
    port = _closed_port()
    offered = 400
    for i in range(offered):
        send_udp(port + i + 1, b"p")
    time.sleep(0.4)
    capped = target.snapshot_capped("net")
    after = target.snapshot("net")
    mine = [r for r in _records(capped) if r.get("address") == "127.0.0.1"]
    used = _int((capped.get("interval") or {}).get("used"))
    lost_after = _int((after.get("interval") or {}).get("lost"))
    if not control_ok:
        verdict = "inconclusive"
    elif len(mine) < offered and lost_after > 0:
        verdict = "lost"
    elif len(mine) < offered:
        verdict = "survived"
    else:
        verdict = "survived"
    return Finding(
        name="export_partial",
        family="export",
        expected="lost",
        verdict=verdict,
        basis="observed",
        claim="an export that stops before the last record destroys the rest and "
        "reports it in the next header, in the stream it is about",
        evidence={
            "control": control,
            "offered": offered,
            "capped_records": len(mine),
            "interval_used": used,
            "next_lost": lost_after,
            "capped_interval": capped.get("interval"),
            "next_interval": after.get("interval"),
        },
        notes=[
            "obs_table.h:155-171: flip() clears an undrained buffer into lost",
            (
                "obs_table.h:379-395: lost is zeroed only when a pass reaches the "
                "last record"
            ),
            (
                "shirudo's own reader takes the whole interval, so this scenario "
                "asks whether anything is destroyed when it does"
            ),
            (
                "survived here is not a claim that the loss path is dead: it is a "
                "claim that shirudo's own read never leaves the it half-drained, so "
                "on this target the path modelled as lost is never taken"
            ),
        ],
    )


SCENARIOS = {
    "attribution_blank": scn_attribution_blank,
    "unsocketed_packet": scn_unsocketed_packet,
    "dns_offport": scn_dns_offport,
    "dns_qtype_txt": scn_dns_qtype_txt,
    "dns_nxdomain": scn_dns_nxdomain,
    "dns_name_launder": scn_dns_name_launder,
    "dns_id_confusion": scn_dns_id_confusion,
    "bucket_collision": scn_bucket_collision,
    "export_stall": scn_export_stall,
    "export_partial": scn_export_partial,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        choices=sorted(SCENARIOS),
        help="run one scenario, repeatable",
    )
    parser.add_argument(
        "--json", dest="json_path", default=None, help="write the findings to this path"
    )
    args = parser.parse_args(argv)

    target = Target()
    print(f"upatch list: {target.ensure_loaded().strip()[:200]}", flush=True)
    names = args.only or list(SCENARIOS)
    findings = []
    for name in names:
        started = time.time()
        try:
            finding = SCENARIOS[name](target)
        except Exception as exc:  # a scenario that cannot run is not a finding
            finding = Finding(
                name=name,
                family="?",
                expected="?",
                verdict="error",
                basis="observed",
                claim=str(exc)[:300],
            )
        finding.evidence.setdefault("seconds", round(time.time() - started, 2))
        findings.append(finding)
        print(finding.line(), flush=True)
        if finding.verdict == "error":
            print(f"    {finding.claim}", flush=True)

    doc = {
        "target": "shirudo test VM",
        "upatch": UPATCH,
        "target_facts": target_facts(target),
        "findings": [f.to_dict() for f in findings],
    }
    if args.json_path:
        with open(args.json_path, "w") as handle:
            json.dump(doc, handle, indent=1, sort_keys=True)
    print(json.dumps({"verdicts": {f.name: f.verdict for f in findings}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
