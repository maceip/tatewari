"""A model of shirudo's kernel-obs evidence pipeline.

The traffic the scenarios drive is real: real sockets, real bytes, real DNS
packets. This file decides what the kernel would have written down about it.

Every constant and branch below is a port of a named line in
``shirudo/upatches/kernel-obs/``. Where this model and that code disagree, that
code is right. The mappings are:

  ``ArenaTable``      obs_table.h:55-200, 300-400 -- the double-buffered arena
                      table, its bounded probe chain, its refusal counters and
                      the flip/clear/destroy sequence the serializer runs.
  ``NetObserver``     obs_net.bpf.c:151-153 (sizing), :960-1010 (attribution),
                      :110-140 (the serialized record).
  ``DnsObserver``     obs_dns.bpf.c:11-29 (limits), :600-663 (query),
                      :735-800 (response), :272-300 (name slots).
  ``observer_clock``  obs_common.h:175-178, ``bpf_ktime_get_boot_ns``.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

U64 = 0xFFFFFFFFFFFFFFFF

# Sizing, verbatim: obs_net.bpf.c:151-153 and obs_dns.bpf.c:167-169.
NET_CAPACITY = 8192
NET_BUCKETS = 4096
DNS_CAPACITY = 1024
DNS_BUCKETS = 512
TABLE_STEPS = 8

# obs_dns.bpf.c:11-26.
DNS_PORT = 53
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_MAX_NAMES_PER_IP = 4
DNS_REQ_MAP_ENTRIES = 1024

# obs_common.h:110-115.
ROLE_NONE = 0
ROLE_INITIATOR = 1
ROLE_ACCEPTOR = 2
ROLE_LISTENER = 3

HIT = "hit"
CREATED = "created"
REFUSED_OVERFLOW = "overflow"
REFUSED_CAS = "cas"


def hash_mix(h: int, v: int) -> int:
    """obs_common.h:185-192, in u64 arithmetic."""
    h ^= (v + 0x9E3779B97F4A7C15 + ((h << 6) & U64) + (h >> 2)) & U64
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & U64
    h ^= h >> 33
    return h & U64


def hash_words(words: list[int]) -> int:
    """obs_common.h:326-336."""
    h = 0
    for word in words:
        h = hash_mix(h, word)
    return h & 0xFFFFFFFF


def ipv4_addr_words(ip: str) -> list[int]:
    """`__u32 addr[4]`, network order, IPv4 in addr[0] -- obs_net.bpf.c:45."""
    raw = socket.inet_aton(ip)
    return [struct.unpack("<I", raw)[0], 0, 0, 0]


@dataclass(frozen=True)
class Exe:
    """struct obs_exe -- obs_common.h:90-94. What names a process."""

    ino: int
    dev: int


@dataclass(frozen=True)
class Ident:
    """struct obs_ident -- obs_common.h:96-99."""

    exe: Exe | None
    cgroup: int | None


@dataclass(frozen=True)
class SockFact:
    """What obs_net.bpf.c:960-978 can recover from a packet's socket.

    ``sk_storage`` is whether ``bpf_sk_storage_get`` found the record the
    observer attaches in ``lsm/socket_post_create``. ``skb_sk`` is whether the
    skb carries a socket at all: cgroup_skb programs only run for a full
    socket, so a skb without one produces no record.
    """

    skb_sk: bool
    sk_storage: bool = True
    exe: Exe | None = None
    cgroup: int | None = None
    role: int = ROLE_INITIATOR


def net_key_words(ident: Ident, family: int, proto: int, role: int,
                  port: int, addr: list[int]) -> list[int]:
    """The little-endian words of ``struct net_key`` (obs_net.bpf.c:35-46).

    Layout: ino, dev|pad, cgroup, family|proto|role|pad0|port|pad1,
    addr[0]|addr[1], addr[2]|addr[3].
    """
    ino = ident.exe.ino if ident.exe else 0
    dev = ident.exe.dev if ident.exe else 0
    cgroup = ident.cgroup if ident.cgroup is not None else 0
    word3 = (
        (family & 0xFF)
        | ((proto & 0xFF) << 8)
        | ((role & 0xFF) << 16)
        | ((port & 0xFFFF) << 32)
    )
    return [
        ino & U64,
        (dev & 0xFFFFFFFF) & U64,
        cgroup & U64,
        word3,
        ((addr[0] & 0xFFFFFFFF) | ((addr[1] & 0xFFFFFFFF) << 32)) & U64,
        ((addr[2] & 0xFFFFFFFF) | ((addr[3] & 0xFFFFFFFF) << 32)) & U64,
    ]


@dataclass
class Export:
    """One serialized snapshot, as the exporter would hand it to the collector."""

    table: str
    boot_now_ns: int
    since_ns: int
    used: int
    overflow: int
    lost: int
    done: bool
    peek: bool
    records: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "table": self.table,
            "boot_now_ns": self.boot_now_ns,
            "since_ns": self.since_ns,
            "used": self.used,
            "overflow": self.overflow,
            "lost": self.lost,
            "done": self.done,
            "peek": self.peek,
            "records": list(self.records),
        }


class _State:
    """struct <table>_table_state -- obs_table.h:48-54."""

    def __init__(self, buckets: int, capacity: int) -> None:
        self.buckets = buckets
        self.capacity = capacity
        self.next_slot = 1
        self.overflow = 0
        self.since_ns = 0
        self.heads = [0] * buckets
        self.entries: list[dict | None] = [None] * (capacity + 1)

    def clear(self) -> None:
        for i in range(self.buckets):
            self.heads[i] = 0
        self.overflow = 0
        self.next_slot = 1


class ArenaTable:
    """obs_table.h -- hooks append into the active buffer, the serializer flips."""

    def __init__(self, name: str, capacity: int, buckets: int) -> None:
        self.name = name
        self.capacity = capacity
        self.buckets = buckets
        self.states = [_State(buckets, capacity), _State(buckets, capacity)]
        self.active = 0
        self.drain = 1
        self.lost = 0
        self.cursor = 0
        self.exported: list[Export] = []
        self.refusals = 0
        self.duplicates = 0

    # -- hook side -----------------------------------------------------------
    def touch(self, words: list[int], key: tuple) -> tuple[dict | None, str]:
        state = self.states[self.active]
        bucket = hash_words(words) & (self.buckets - 1)
        idx = state.heads[bucket]
        for _ in range(TABLE_STEPS):
            if idx == 0 or idx > self.capacity:
                break
            entry = state.entries[idx]
            if entry is not None and entry["used"] and entry["words"] == words:
                return entry, HIT
            idx = entry["next"] if entry is not None else 0

        idx = state.next_slot
        state.next_slot += 1
        if idx == 0 or idx > self.capacity:
            state.overflow += 1
            self.refusals += 1
            return None, REFUSED_OVERFLOW
        entry = {
            "next": state.heads[bucket],
            "used": True,
            "key": key,
            "words": words,
            "bucket": bucket,
            "val": {},
        }
        state.entries[idx] = entry
        state.heads[bucket] = idx
        return entry, CREATED

    def entries(self) -> list[dict]:
        state = self.states[self.active]
        return [e for e in state.entries[1:] if e is not None and e["used"]]

    # -- serializer side -----------------------------------------------------
    def _flip(self, now_ns: int) -> None:
        """obs_table.h:155-171: an interval that was never drained is destroyed."""
        spare = self.states[self.drain]
        if spare.next_slot != 1:
            n = min(spare.next_slot - 1, self.capacity)
            self.lost += n
            spare.clear()
        spare.since_ns = now_ns
        self.active, self.drain = self.drain, self.active

    def export(self, now_ns: int, *, peek: bool = False,
               ship: int | None = None, resume: bool = False) -> Export:
        """One serializer pass. ``ship`` models a page-level stop.

        The cursor belongs to the caller (obs_table.h:336 reads ``ctx->cursor``),
        so ``resume=False`` is the exporter starting an interval at cursor 0 --
        which flips. :379-395 clears the buffer and zeroes ``lost`` only when the
        pass reaches the last record.
        """
        if peek:
            state = self.states[self.active]
        else:
            if not resume:
                self.cursor = 0
            if self.cursor == 0:
                self._flip(now_ns)
            state = self.states[self.drain]
        # The header carries the loss the flip just recorded, then completion
        # zeroes it: obs_table.h:360 emits, :392 clears.
        lost_header = self.lost

        used = min(max(0, state.next_slot - 1), self.capacity)
        start = self.cursor
        end = used if ship is None else min(used, start + max(0, ship))
        records = [
            self._record(state.entries[i]) for i in range(start + 1, end + 1)
            if state.entries[i] is not None
        ]
        done = end >= used
        export = Export(
            table=self.name,
            boot_now_ns=now_ns,
            since_ns=state.since_ns,
            used=used,
            overflow=state.overflow,
            lost=lost_header,
            done=done,
            peek=peek,
            records=records,
        )
        if done and not peek:
            state.clear()
            self.lost = 0
            self.cursor = 0
        else:
            self.cursor = end
        self.exported.append(export)
        return export

    def _record(self, entry: dict) -> dict:
        return {"key": entry["key"], **entry["val"]}


def _skb_len(payload: int, proto: int) -> int:
    """skb->len for a locally generated datagram: L3 + L4(+payload)."""
    if proto == 6:  # TCP
        return payload + 40
    return payload + 28


class NetObserver:
    """obs_net.bpf.c -- cgroup_skb/egress and ingress packet accounting."""

    def __init__(self, capacity: int = NET_CAPACITY,
                 buckets: int = NET_BUCKETS) -> None:
        self.table = ArenaTable("net", capacity, buckets)
        self.dropped_no_socket = 0
        self.unattributed = 0

    def packet(self, *, egress: bool, src: str, dst: str, sport: int, dport: int,
               proto: int, payload: int, now_ns: int,
               sock: SockFact | None = None,
               pid: int | None = None) -> dict | None:
        if sock is None or not sock.skb_sk:
            self.dropped_no_socket += 1
            return None

        if sock.sk_storage:
            ident = Ident(exe=sock.exe, cgroup=sock.cgroup)
        else:
            ident = Ident(exe=None, cgroup=sock.cgroup)
            self.unattributed += 1

        role = sock.role
        port = 0
        if role not in (ROLE_ACCEPTOR, ROLE_LISTENER):
            port = dport if egress else sport
        addr = ipv4_addr_words(dst if egress else src)
        words = net_key_words(ident, socket.AF_INET, proto, role, port, addr)
        key = (
            "net", ident.exe.ino if ident.exe else None,
            ident.exe.dev if ident.exe else None, ident.cgroup,
            proto, role, port, dst if egress else src,
        )
        entry, status = self.table.touch(words, key)
        if entry is None:
            return None
        val = entry["val"]
        val.setdefault("first_ns", now_ns)
        val.setdefault("pid", pid)
        val["last_ns"] = now_ns
        val["count"] = int(val.get("count", 0)) + 1
        if egress:
            val["tx_pkts"] = int(val.get("tx_pkts", 0)) + 1
            val["tx_bytes"] = int(val.get("tx_bytes", 0)) + _skb_len(payload, proto)
        else:
            val["rx_pkts"] = int(val.get("rx_pkts", 0)) + 1
            val["rx_bytes"] = int(val.get("rx_bytes", 0)) + payload + 28
        return entry

    def export(self, now_ns: int, **kwargs) -> Export:
        return self.table.export(now_ns, **kwargs)


class DnsObserver:
    """obs_dns.bpf.c -- a query/response join that keeps names, not payloads."""

    def __init__(self, capacity: int = DNS_CAPACITY,
                 buckets: int = DNS_BUCKETS, resolver_port: int = DNS_PORT) -> None:
        self.table = ArenaTable("dns", capacity, buckets)
        self.pending: dict[tuple, dict] = {}
        self.debug: dict[str, int] = {}
        self.dropped = 0
        # The resolver the target is configured with; 53 in a deployment. The
        # demo remaps it only so it never needs to bind a privileged port.
        self.resolver_port = resolver_port

    def _debug(self, name: str) -> None:
        """obs_dns.bpf.c:179-187: counted in ``obs_i_dns_dbg``, never exported."""
        self.debug[name] = self.debug.get(name, 0) + 1

    def query(self, *, name: str, qtype: int, qid: int, dst: str, sport: int,
              dport: int, family: int = socket.AF_INET,
              ident: Ident | None = None, now_ns: int = 0) -> str | None:
        if dport != self.resolver_port:
            # obs_dns.bpf.c:828, before any counter: not even a debug tick.
            return None
        self._debug("query_packet")
        if qtype not in (DNS_TYPE_A, DNS_TYPE_AAAA):
            self._debug("query_qtype_unsupported")
            self.dropped += 1
            return None
        ident = ident or Ident(exe=None, cgroup=None)
        key = (family, dst, sport, qid)
        if key not in self.pending and len(self.pending) >= DNS_REQ_MAP_ENTRIES:
            oldest = next(iter(self.pending))
            del self.pending[oldest]
        self.pending[key] = {"name": name, "qtype": qtype, "ident": ident}
        self._debug("query_stored")
        return "stored"

    def response(self, *, qid: int, dst: str, client_port: int, sport: int,
                 qtype: int, answers: list[str], ancount: int,
                 family: int = socket.AF_INET, now_ns: int = 0) -> str | None:
        if sport != self.resolver_port:
            return None
        self._debug("resp_packet")
        if ancount == 0:
            self._debug("resp_no_answer")
            self.dropped += 1
            return None
        # obs_dns.bpf.c:106-110: the query key is the client-to-resolver tuple,
        # so an ingress response reverses its ports and produces the same key.
        key = (family, dst, client_port, qid)
        req = self.pending.get(key)
        if req is None:
            self._debug("resp_req_miss")
            self.dropped += 1
            return None
        if qtype != req["qtype"]:
            self._debug("resp_qtype_mismatch")
            del self.pending[key]
            self.dropped += 1
            return None
        del self.pending[key]
        for answer in answers:
            ident = req["ident"]
            addr = ipv4_addr_words(answer)
            words = net_key_words(ident, family, 0, 0, 0, addr)
            k = ("dns", ident.exe.ino if ident.exe else None,
                 ident.cgroup, answer)
            entry, status = self.table.touch(words, k)
            if entry is None:
                continue
            val = entry["val"]
            val.setdefault("first_ns", now_ns)
            val["last_ns"] = now_ns
            val["count"] = int(val.get("count", 0)) + 1
            self._name_touch(val, req["name"], now_ns)
        return "recorded"

    def _name_touch(self, val: dict, name: str, now_ns: int) -> None:
        """obs_dns.bpf.c:272-300: four slots per address, the oldest gives way."""
        slots = val.setdefault("names", [])
        for slot in slots:
            if slot["name"] == name:
                slot["seen"] += 1
                slot["last_ns"] = now_ns
                return
        if len(slots) < DNS_MAX_NAMES_PER_IP:
            slots.append({"name": name, "seen": 1, "last_ns": now_ns})
            return
        oldest = min(range(len(slots)), key=lambda i: slots[i]["last_ns"])
        slots[oldest] = {"name": name, "seen": 1, "last_ns": now_ns}

    def export(self, now_ns: int, **kwargs) -> Export:
        return self.table.export(now_ns, **kwargs)


@dataclass
class KernelObs:
    """The two tables the evidence-plane scenarios attack."""

    net: NetObserver = field(default_factory=NetObserver)
    dns: DnsObserver = field(default_factory=DnsObserver)

    def export_all(self, now_ns: int, *, ship: int | None = None) -> list[Export]:
        return [
            self.net.export(now_ns, ship=ship),
            self.dns.export(now_ns, ship=ship),
        ]
