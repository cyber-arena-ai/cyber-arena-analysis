# knadh/listmonk overlap

> Maintainer-only pre-semantic overlap report. Keep out of agent/researcher prompts and challenge workspaces.

- Hard-gated components: 3
- Exact affected-unit lanes: 2
- Date cutoff: `2026-02-16T23:59:59+00:00`
- Evidence: exact OSV `affected.versions` matches; unresolved ranges are not treated as absence.

## Affected-unit overlap

| Affected unit | Checkpoints | Maximum reported overlap | Distinct maximal groups | Provisional review components | Range gaps at maxima |
| --- | ---: | ---: | --- | --- | --- |
| `GIT:knadh/listmonk` | 41 | 3 | 1 | `CVE-2026-34584`, `CVE-2026-34828`, `CVE-2026-62361` | — |
| `Go:github.com/knadh/listmonk` | 0 | 0 | 0 | — | — |

## Distinct maximal groups

- `GIT:knadh/listmonk` group 1: `CVE-2026-34584`, `CVE-2026-34828`, `CVE-2026-62361`; 8 checkpoint label(s), including `nightly`, `v4.1.0`, `v5.0.0` (+5).

## Mandatory stops before semantic filtering

- Evaluate native/Git ranges before treating the reported maximum as exhaustive.
- Do not apply semantic verdicts until these programmatic range gaps are resolved or explicitly retained as uncertainty.

The full checkpoint matrices are retained in the adjacent JSON file.
