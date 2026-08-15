# knadh/listmonk commit-resolved candidate windows

> Maintainer-only pre-semantic report. States are OSV claims evaluated on the upstream Git graph, not reproduced vulnerabilities.

- Input components: 3
- Accepted components: 3
- Rejected components: 0
- Components whose OSV range begins at repository origin: 1
- Fix-boundary checkpoints evaluated: 5
- Distinct historical windows: 3
- Windows retained for semantic review: 3
- Maximum reported overlap: 3
- Upstream HEAD observed: `911e0b774abad4fbf7b534be43a34a80fb6ace5b`
- HEAD has no known applicable retained component: `true`

## Candidate windows

| Window | Checkpoint | Reported advisories | Stable tag | Selection reason |
| --- | --- | ---: | --- | --- |
| W1 | `171a597ff2f20e29dad9894418a4934f9ed30a58` | 3 | — | `widest_reported_overlap` |

W1 reported advisories: `CVE-2026-34584`, `CVE-2026-34828`, `CVE-2026-62361`
| W2 | `347f5976759232c36e571cf58b4bfe33c2794f35` | 2 | — | `marginal_component_set_diversity` |

W2 reported advisories: `CVE-2026-34828`, `CVE-2026-62361`
| W3 | `e3499cf722155a11b8ca1a2baec3c09a61b9e1ed` | 1 | — | `marginal_component_set_diversity` |

W3 reported advisories: `CVE-2026-62361`

## Historical window chronology

- H1: `171a597ff2f20e29dad9894418a4934f9ed30a58` (2026-03-21T05:24:13+00:00), 3 reported advisories.
- H2: `347f5976759232c36e571cf58b4bfe33c2794f35` (2026-03-23T11:07:22+00:00), 2 reported advisories.
- H3: `e3499cf722155a11b8ca1a2baec3c09a61b9e1ed` (2026-06-19T10:06:47+00:00), 1 reported advisories.

## Programmatic exclusions

- None.

## Stop boundary

These windows are ready for budgeted semantic review only. No application-fit, reachability, scope, PoC, build, exploit, attack-depth, or defense-depth judgment has been performed.
