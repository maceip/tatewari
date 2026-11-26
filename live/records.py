# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of tatewari
"""Parse the chunks shirudo's own serializer emitted.

The layout is read off ``upatches/kernel-obs/`` and is not guessed:

  ``obs_table.h:191-200``    page_slot -> (chunk key, offset), offset = slot*record
  ``obs_table.h:233-264``    the per-page header at slot 0 of chunk 0
  ``obs_table.h:285-310``    each data record: idx, flags, then the table's emit
  ``obs_net.bpf.c:159-172``  the net record fields and their offsets
  ``obs_dns.bpf.c:194-218``  the dns record fields, four names of 272 bytes

The only thing this module adds is a struct unpack. Every value it reports was
written by the kernel running their program.
"""

from __future__ import annotations

import os
import struct

SERIAL_MAGIC = 0x5A4C5253
CHUNK_BYTES = 4096
CHUNK_HEADER = 64
CHUNK_PAYLOAD = 4032
PAGE_CHUNKS = 4
RECORD_PRESENT = 1

TABLE_MAGIC = {"net": 0x5445454E, "dns": 0x41534E44}
RECORD_SIZE = {"net": 120, "dns": 1168}


def load_chunks(root: str, table: str, seq: int) -> dict[int, bytes]:
    """Read the chunk files the probe wrote, keyed by chunk_index."""
    path = os.path.join(root, table, str(seq))
    chunks: dict[int, bytes] = {}
    if not os.path.isdir(path):
        return chunks
    for name in sorted(os.listdir(path)):
        if not name.endswith(".bin"):
            continue
        with open(os.path.join(path, name), "rb") as handle:
            raw = handle.read()
        if len(raw) != CHUNK_BYTES:
            continue
        fields = struct.unpack("<IIIiIIIIIIQQQ", raw[:CHUNK_HEADER])
        if fields[0] != SERIAL_MAGIC:
            continue
        chunks[fields[4]] = raw
    return chunks


def _ip(word: int) -> str:
    return ".".join(str(byte) for byte in word.to_bytes(4, "little"))


def _parse_header(table: str, record: bytes) -> dict:
    (
        magic,
        version,
        header_size,
        record_size,
        per_page,
        capacity,
        buckets,
        key_size,
        val_size,
        flags,
        now_ns,
        since_ns,
        used,
        overflow,
        lost,
    ) = struct.unpack("<IHHHHIIIIIIQQIIII", record[:64])
    return {
        "magic_ok": magic == TABLE_MAGIC[table],
        "version": version,
        "header_size": header_size,
        "record_size": record_size,
        "records_per_page": per_page,
        "capacity": capacity,
        "buckets": buckets,
        "key_size": key_size,
        "val_size": val_size,
        "flags": flags,
        "boot_now_ns": now_ns,
        "since_ns": since_ns,
        "used": used,
        "overflow": overflow,
        "lost": lost,
    }


def _parse_net(record: bytes) -> dict:
    (dev,) = struct.unpack("<I", record[8:12])
    (ino,) = struct.unpack("<Q", record[16:24])
    (cgroup,) = struct.unpack("<Q", record[24:32])
    family, proto, role = record[32], record[33], record[34]
    (port,) = struct.unpack("<H", record[36:38])
    addr = struct.unpack("<IIII", record[40:56])
    count, first, last, tx_pkts, tx_bytes, rx_pkts, rx_bytes = struct.unpack(
        "<QQQQQQQ", record[56:112]
    )
    (pid,) = struct.unpack("<I", record[112:116])
    return {
        "dev": dev,
        "ino": ino,
        "cgroup": cgroup,
        "family": family,
        "proto": proto,
        "role": role,
        "port": port,
        "addr": list(addr),
        "ip": _ip(addr[0]) if family == 2 else "",
        "count": count,
        "first_ns": first,
        "last_ns": last,
        "tx_pkts": tx_pkts,
        "tx_bytes": tx_bytes,
        "rx_pkts": rx_pkts,
        "rx_bytes": rx_bytes,
        "pid": pid,
    }


def _parse_dns(record: bytes) -> dict:
    (dev,) = struct.unpack("<I", record[8:12])
    (ino,) = struct.unpack("<Q", record[16:24])
    (cgroup,) = struct.unpack("<Q", record[24:32])
    family = record[32]
    addr = struct.unpack("<IIII", record[40:56])
    count, first, last = struct.unpack("<QQQ", record[56:80])
    names = []
    for index in range(4):
        base = 80 + index * 272
        seen, last_ns = struct.unpack("<QQ", record[base : base + 16])
        if not seen:
            continue
        raw = record[base + 16 : base + 16 + 256]
        names.append(
            {
                "name": raw.split(b"\x00", 1)[0].decode("ascii", "replace"),
                "seen": seen,
                "last_ns": last_ns,
            }
        )
    return {
        "dev": dev,
        "ino": ino,
        "cgroup": cgroup,
        "family": family,
        "addr": list(addr),
        "ip": _ip(addr[0]) if family == 2 else "",
        "count": count,
        "first_ns": first,
        "last_ns": last,
        "names": names,
    }


def parse(root: str, table: str, seq: int) -> dict:
    """Every record the kernel emitted for this table, across all pages."""
    chunks = load_chunks(root, table, seq)
    size = RECORD_SIZE[table]
    per_chunk = CHUNK_PAYLOAD // size
    per_page = per_chunk * PAGE_CHUNKS
    header: dict = {}
    records: list[dict] = []
    pages = sorted({key // PAGE_CHUNKS for key in chunks})
    for page in pages:
        for page_slot in range(per_page):
            key, slot = divmod(page_slot, per_chunk)
            raw = chunks.get(page * PAGE_CHUNKS + key)
            if raw is None:
                continue
            offset = CHUNK_HEADER + slot * size
            record = raw[offset : offset + size]
            if len(record) < size:
                continue
            if page_slot == 0:
                if not header:
                    header = _parse_header(table, record)
                continue
            index, flags = struct.unpack("<II", record[:8])
            if not index or not (flags & RECORD_PRESENT):
                continue
            records.append(_parse_net(record) if table == "net" else _parse_dns(record))
    return {"header": header, "records": records}
