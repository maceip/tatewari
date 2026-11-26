# Security Policy

Please do not report security vulnerabilities in public issues or discussions.
Instead, use GitHub's
[**Report a vulnerability**](https://github.com/maceip/tatewari/security/advisories/new)
feature.

## Scope

tatewari is a demonstration harness. The scenarios in this repo show documented
behavior of a metadata-only observer; a scenario reaching its predicted verdict
is the demo working, not a vulnerability in itself.

Route reports to where the code lives:

- **This repo** (`tatewari/`, `live/`, `observed/`, the harness and the model):
  report here.
- **The egress implementation** (encoders, sink, missions, oracle, reference
  target): lives in [maceip/spar](https://github.com/maceip/spar); report there.
- **shirudo itself** (the kernel-obs upatch, the loader, the exporter): follow
  [shirudo's security policy](https://github.com/shirudo-dev/shirudo/blob/main/SECURITY.md).
  The observed run in `observed/` was taken against shirudo's own test target.
