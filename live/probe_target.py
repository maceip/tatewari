"""Drive the evidence-plane attacks against a real kernel running kernel-obs.

Runs on the target, next to a loaded upatch. The probe daemon attaches the two
cgroup_skb programs to a cgroup this process is moved into, so every packet the
attacks send is genuinely observed; dumps go through the upatch's own serializer.

Nothing here decides what a record says. It sends traffic, asks for the
snapshot, and checks the snapshot against what it sent.

    python3 -m live.probe_target --cgroup /sys/fs/cgroup/obsprobe \
        --daemon ./live/kernel_obs_probe --out findings.json
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from live import records as rec  # noqa: E402
from tatewari.evidence_pipeline import (  # noqa: E402
    Resolver,
    UdpSink,
    _build_query,
    query_once,
    send_udp,
)
from tatewari.observer_model import (  # noqa: E402
    ROLE_INITIATOR,
    Exe,
    Ident,
    hash_words,
    ipv4_addr_words,
    net_key_words,
)

OBS_ROOT = "/tmp/obs"
DNS_PORT = 53
DNS_TYPE_TXT = 16
EXE = Exe(ino=7788, dev=2049)
CGROUP = 4411


class Daemon:
    def __init__(self, path: str, cgroup: str, obj: str) -> None:
        self.proc = subprocess.Popen(
            [path, cgroup, obj], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)
        line = self.proc.stdout.readline().strip()
        if line != "ready":
            raise RuntimeError(f"daemon did not start: {line!r}")
        self.seq = 0

    def dump(self, table: str, pages: int = 256) -> dict:
        command = f"dump {table}" if pages > 1 else f"dump1 {table}"
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline().strip()
        parts = reply.split()
        if not parts or parts[0] != "done":
            raise RuntimeError(f"dump failed: {reply!r}")
        table_out, seq, chunks = parts[1], int(parts[2]), int(parts[3])
        return rec.parse(OBS_ROOT, table_out, seq)

    def close(self) -> None:
        try:
            self.proc.stdin.write("exit\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass
        self.proc.wait(timeout=10)


def finding(name: str, family: str, expected: str, verdict: str, claim: str,
            evidence: dict, notes: list[str]) -> dict:
    return {"scenario": name, "family": family, "expected": expected,
            "verdict": verdict, "basis": "observed-live", "claim": claim,
            "notes": notes, "evidence": evidence}


def net_peers(snapshot: dict, port: int, ip: str = "127.0.0.1") -> list[dict]:
    return [r for r in snapshot["records"]
            if r["port"] == port and r["ip"] == ip]


# --------------------------------------------------------------------------


def scn_export_partial(daemon: Daemon) -> dict:
    carrier = 41000
    filler_ports = list(range(42000, 42140))
    for port in filler_ports:
        send_udp(port, b"f")
    send_udp(carrier, b"canary-page-two")
    first = daemon.dump("net", pages=1)
    second = daemon.dump("net")
    seen_first = bool(net_peers(first, carrier))
    seen_second = bool(net_peers(second, carrier))
    verdict = "lost" if not seen_first and not seen_second and \
        second["header"].get("lost", 0) > 0 else "survived"
    return finding(
        "export_partial", "export", "lost", verdict,
        "the kernel held the record; abandoning one page destroyed the rest",
        {"first_page_header": first["header"],
         "first_page_records": len(first["records"]),
         "restart_header": second["header"],
         "restart_records": len(second["records"]),
         "carrier_port": carrier, "carrier_in_first": seen_first,
         "carrier_in_restart": seen_second},
        ["one dump of page 0, then a fresh pass at cursor 0, as the exporter "
         "does when a page fails"],
    )


def scn_export_stall(daemon: Daemon) -> dict:
    capacity = 8192
    first_port = 1024
    carrier = 41500
    for index in range(capacity):
        send_udp(first_port + index, b"f")
    send_udp(carrier, b"canary-refused")
    snapshot = daemon.dump("net")
    present_carrier = bool(net_peers(snapshot, carrier))
    present_first = bool(net_peers(snapshot, first_port))
    overflow = snapshot["header"].get("overflow", 0)
    verdict = "refused" if not present_carrier and present_first and \
        overflow > 0 else "survived"
    return finding(
        "export_stall", "export", "refused", verdict,
        "refusal at capacity falls on insertion order, not on importance",
        {"sent": capacity + 1, "overflow": overflow,
         "carrier_port": carrier, "carrier_present": present_carrier,
         "first_filler_present": present_first,
         "used": snapshot["header"].get("used")},
        ["8193 distinct peers into an 8192-entry table; the last one in is "
         "the one that is refused"],
    )


def scn_attribution_fields(daemon: Daemon) -> dict:
    sink = UdpSink()
    port = sink.port
    try:
        send_udp(port, b"canary-attributed")
        sink.wait(1)
    finally:
        sink.close()
    snapshot = daemon.dump("net")
    peers = net_peers(snapshot, port)
    attributed = [r for r in peers if r["ino"] or r["dev"] or r["cgroup"]]
    verdict = "attributed" if attributed else "blank"
    return finding(
        "attribution_fields", "identity", "attributed", verdict,
        "a real record carries the binary's inode, device and cgroup",
        {"peers": peers, "attributed": len(attributed),
         "header": snapshot["header"]},
        ["this is the positive half of the model's attribution claim, read "
         "from the kernel's own record"],
    )


def scn_dns_offport(daemon: Daemon) -> dict:
    resolver = Resolver(mode="a", answer="127.0.0.9", port=5353)
    try:
        query = query_once(resolver.port, "quiet.example")
        resolver.wait(1)
        dport = resolver.port
    finally:
        resolver.close()
    snapshot = daemon.dump("dns")
    net = daemon.dump("net")
    peers = [r for r in net["records"] if r["port"] == dport]
    verdict = "unjoined" if query["answers"] and not snapshot["records"] \
        and peers else "survived"
    return finding(
        "dns_offport", "name_join", "unjoined", verdict,
        "a real answer came back over a port the observer does not parse",
        {"query": query, "dns_records": snapshot["records"],
         "net_peers_on_that_port": peers},
        ["the observer parses answers only from port 53; port 5353 is "
         "invisible to the dns table while the bytes are counted"],
    )


def scn_dns_qtype_txt(daemon: Daemon) -> dict:
    resolver = Resolver(mode="txt", port=53, host="127.0.0.2")
    try:
        query = query_once(resolver.port, "spf.example", DNS_TYPE_TXT,
                           host="127.0.0.2")
        resolver.wait(1)
    finally:
        resolver.close()
    snapshot = daemon.dump("dns")
    verdict = "unjoined" if query["ancount"] and not snapshot["records"] \
        else "survived"
    return finding(
        "dns_qtype_txt", "name_join", "unjoined", verdict,
        "a TXT answer is a real answer; the observer parses only A and AAAA",
        {"query": query, "dns_records": snapshot["records"]},
        ["the refusal is counted in obs_i_dns_dbg, which the snapshot does "
         "not contain: no field in the record mentions it"],
    )


def scn_dns_nxdomain(daemon: Daemon) -> dict:
    canary = b"\xa7"
    bits = [(canary[0] >> i) & 1 for i in range(8)]
    resolver = Resolver(mode="bits", port=53, host="127.0.0.2")
    queries = []
    try:
        for index, bit in enumerate(bits):
            name = f"b{index}.{'y' if bit else 'n'}.probe.test"
            queries.append(query_once(resolver.port, name, host="127.0.0.2"))
        resolver.wait(8)
    finally:
        resolver.close()
    snapshot = daemon.dump("dns")
    present = {r["ip"] for r in snapshot["records"]}
    decoded = 0
    for index in range(8):
        if f"127.0.0.{index + 1}" in present:
            decoded |= 1 << index
    verdict = "unrecorded" if decoded == canary[0] and sum(bits) < 8 \
        else "survived"
    return finding(
        "dns_nxdomain", "name_join", "unrecorded", verdict,
        f"eight real queries carried byte {canary.hex()}; the byte decoded "
        "back out of the kernel's own table",
        {"bits": bits, "sent": canary.hex(), "decoded": bytes([decoded]).hex(),
         "queries": queries, "dns_records": snapshot["records"]},
        ["a query that does not resolve leaves no record at all, so absence "
         "is the carrier"],
    )


def scn_dns_name_launder(daemon: Daemon) -> dict:
    covert = "canary-9f2c1a.exfil.example"
    names = [covert] + [f"telemetry-{i}.cdn.example" for i in range(4)]
    resolver = Resolver(mode="a", answer="127.0.0.9", port=53, host="127.0.0.2")
    try:
        for name in names:
            query_once(resolver.port, name, host="127.0.0.2")
        resolver.wait(len(names))
    finally:
        resolver.close()
    snapshot = daemon.dump("dns")
    recorded = [slot["name"] for r in snapshot["records"]
                for slot in r["names"]]
    verdict = "evicted" if covert not in recorded and len(recorded) == 4 \
        else "survived"
    return finding(
        "dns_name_launder", "name_join", "evicted", verdict,
        "five real resolutions of one address: the count stays, the covert "
        "name is pushed out of the four slots",
        {"asked": names, "recorded_names": recorded,
         "dns_records": snapshot["records"]},
        ["four slots per address; the fifth resolution evicts the oldest"],
    )


def scn_dns_id_confusion(daemon: Daemon) -> dict:
    resolver = Resolver(mode="a", answer="127.0.0.20", port=53, host="127.0.0.2")
    name_a, name_b = "bank.example", "cdn.example"
    replies = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sock.bind(("127.0.0.2", 0))
            sock.sendto(_build_query(name_a, 0x4242, 1), ("127.0.0.2", 53))
            sock.sendto(_build_query(name_b, 0x4242, 1), ("127.0.0.2", 53))
            resolver.wait(2)
            for _ in range(2):
                try:
                    sock.recvfrom(4096)
                    replies += 1
                except socket.timeout:
                    break
    finally:
        resolver.close()
    snapshot = daemon.dump("dns")
    recorded = [slot["name"] for r in snapshot["records"]
                for slot in r["names"]]
    verdict = "confused" if recorded and name_a not in recorded else "survived"
    return finding(
        "dns_id_confusion", "name_join", "confused", verdict,
        "two questions in flight under one transaction id: the answer to the "
        "first is filed under the second",
        {"asked": [name_a, name_b], "recorded_names": recorded,
         "replies": replies, "dns_records": snapshot["records"]},
        ["the recorded name comes from the pending question, never from the "
         "answer, so a stale question mislabels it"],
    )


def scn_bucket_collision(daemon: Daemon) -> dict:
    def bucket(port: int) -> int:
        words = net_key_words(Ident(EXE, CGROUP), socket.AF_INET, 17,
                              ROLE_INITIATOR, port,
                              ipv4_addr_words("127.0.0.1"))
        return hash_words(words) & 4095

    groups: dict[int, list[int]] = {}
    carrier_port = fillers = None
    for port in range(20000, 65536):
        members = groups.setdefault(bucket(port), [])
        members.append(port)
        if len(members) == 9:
            carrier_port, fillers = members[0], members[1:]
            break
    control_port = next(p for p in range(20000, 65536)
                        if bucket(p) != bucket(carrier_port))
    send_udp(carrier_port, b"a")
    for port in fillers:
        send_udp(port, b"f")
    send_udp(carrier_port, b"b")
    send_udp(control_port, b"a")
    send_udp(control_port, b"b")
    snapshot = daemon.dump("net")
    carrier = net_peers(snapshot, carrier_port)
    control = net_peers(snapshot, control_port)
    verdict = "split" if len(carrier) > 1 and len(control) == 1 else "survived"
    return finding(
        "bucket_collision", "table", "split", verdict,
        "one peer became two entries: its packet and byte totals severed",
        {"bucket": bucket(carrier_port), "carrier_port": carrier_port,
         "fillers": fillers, "control_port": control_port,
         "carrier_entries": carrier, "control_entries": control},
        ["ports chosen from the same hash the observer uses, then sent for "
         "real; the split is read out of the kernel's table"],
    )


SCENARIOS = {
    "export_partial": scn_export_partial,
    "export_stall": scn_export_stall,
    "attribution_fields": scn_attribution_fields,
    "dns_offport": scn_dns_offport,
    "dns_qtype_txt": scn_dns_qtype_txt,
    "dns_nxdomain": scn_dns_nxdomain,
    "dns_name_launder": scn_dns_name_launder,
    "dns_id_confusion": scn_dns_id_confusion,
    "bucket_collision": scn_bucket_collision,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="live.probe_target")
    parser.add_argument("--cgroup", default="/sys/fs/cgroup/obsprobe")
    parser.add_argument("--daemon", default="./live/kernel_obs_probe")
    parser.add_argument("--object", default="live/kernel-obs.bpf.o")
    parser.add_argument("--out", default="findings-live.json")
    parser.add_argument("--only", default="")
    args = parser.parse_args(argv)

    os.makedirs(args.cgroup, exist_ok=True)
    with open(os.path.join(args.cgroup, "cgroup.procs"), "w") as handle:
        handle.write(str(os.getpid()))

    daemon = Daemon(args.daemon, args.cgroup, args.object)
    only = [s.strip() for s in args.only.split(",") if s.strip()]
    wanted = only or list(SCENARIOS)
    findings = []
    try:
        for name in wanted:
            findings.append(SCENARIOS[name](daemon))
    finally:
        daemon.close()

    result = {"scenarios": len(findings),
              "matched": sum(1 for f in findings
                             if f["verdict"] == f["expected"]),
              "findings": findings}
    with open(args.out, "w") as handle:
        json.dump(result, handle, indent=2)
    for item in findings:
        print(f"{item['scenario']:<22} {item['verdict']:<14} {item['claim']}")
    print(f"\n{result['matched']}/{result['scenarios']} live scenarios reached "
          f"the predicted verdict")
    return 0 if result["matched"] == result["scenarios"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
