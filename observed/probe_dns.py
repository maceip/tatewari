#!/usr/bin/env python3
"""Learn the real `dns` snapshot schema: one query at a local resolver on port 53."""
import json
import subprocess
import sys
import time

sys.path.insert(0, "/workspace/shirudo")
from tatewari.evidence_pipeline import Resolver, query_once  # noqa: E402

SHIRUDO = "/run/shirudo/runtime/usr/bin/shirudo"


def snap(table, peek=False):
    args = [SHIRUDO, "upatch", "map", "kernel-obs", table, "--json", "--show-full"]
    if peek:
        args.append("--peek")
    out = subprocess.run(args, capture_output=True, text=True)
    text = out.stdout.strip()
    start = text.find("{")
    if start < 0:
        return {"error": out.stderr.strip()[:400]}
    return json.loads(text[start:])


res = Resolver(mode="a", answer="127.0.0.9", port=53)
print("resolver on", res.port, flush=True)
snap("dns")  # drain anything earlier
facts = query_once(res.port, "a1b2c3.probe.test", 1)
print("query", facts, flush=True)
time.sleep(0.3)
d = snap("dns")
print(json.dumps(d, indent=1)[:2500], flush=True)
print("--- net for the same peer ---", flush=True)
n = snap("net")
for r in n.get("records", []):
    print(json.dumps(r), flush=True)
res.close()
