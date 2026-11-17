# Security Research Reports

Public vulnerability reports and reproduction materials, maintained by [wtm2648](https://github.com/wtm2648).

Findings are disclosed to the affected upstream projects first; this repository hosts the public copies of the reports (as required by vulnerability databases) together with self-contained reproduction packages.

## Index

| Date | Software | CWE | Vulnerability | Upstream report | Materials |
|---|---|---|---|---|---|
| 2026-11 | [OpENer](https://github.com/EIPStackGroup/OpENer) (EtherNet/IP adapter stack) | [CWE-835](https://cwe.mitre.org/data/definitions/835.html) | Unrecoverable remote DoS: Class 3 connection timeout closes an invalid socket (-1), causing an infinite loop in `RemoveSocketTimerFromList` | [EIPStackGroup/OpENer#621](https://github.com/EIPStackGroup/OpENer/issues/621) | [advisory](reports/2026-11/opener/class3-timeout-wedge/report_documents/ADVISORY.md) · [repro package](reports/2026-11/opener/class3-timeout-wedge/reproduce/opener-wedge-repro.tar.gz) |

## Reproduction packages

Each reproduction package is self-contained: the unmodified upstream source snapshot, a Docker build environment, automated trigger/monitor scripts for every confirmed trigger path, and the captured evidence (GDB backtraces, hardware-watchpoint trace, run logs).
