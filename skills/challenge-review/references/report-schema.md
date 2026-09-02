# Report entry schema

Read this reference only when populating `review.json` after adjudication. The
initializer creates the top-level report, stages, and selected checks. Preserve
those shapes and replace their draft values; add entries to the initially empty
arrays using the contracts below.

Preserve the evidence entries accepted during root adjudication; do not rewrite
their kinds, locators, or observed facts.

Keep each stage and check summary to one conclusion sentence and its evidence
concise. Put supporting analysis only in findings and unresolved concerns.

## Objectives

Each `objectives` entry has exactly these keys:

| Key | Contract |
|---|---|
| `store` | Nonempty store name. Stores are unique for a passing `STATIC-FLAG`. |
| `outcome` | `read`, `write`, or `execute`. |
| `scope` | Registered or custom scope ID; use `null` only when undeclared. |
| `oracle` | `submit` for read/execute or `claim` for write. |

For a verifier-backed review, copy the complete array from `verifier.json`
without modification. For `STATIC`, derive every row from the selected package.

## Findings

Each `findings` entry has exactly these keys:

| Key | Contract |
|---|---|
| `finding_id` | Unique `F-NNN` identifier. |
| `stage` | Selected stage that proves the finding. |
| `severity` | `BLOCKER`, `HIGH`, `MEDIUM`, or `LOW`. |
| `antipattern_id` | Identifier from `antipattern-catalog.md`, or `UNCLASSIFIED`. |
| `title` | Concise description of the defect. |
| `evidence` | Nonempty array of evidence entries. |
| `impact` | Concrete effect on benchmark validity or reproducibility. |
| `required_action` | Smallest action required to resolve the defect. |
| `verdict_effect` | `NONE`, `REVISE`, or `REJECT`. |

Sort findings by severity in the order above, then by `finding_id`.

## Unresolved concerns

Each `unresolved` entry has exactly these keys:

| Key | Contract |
|---|---|
| `concern_id` | Unique `U-NNN` identifier. |
| `stage` | Selected stage in which the uncertainty was found. |
| `check_id` | Selected checklist item left `UNKNOWN`. |
| `concern` | Material undecided property. |
| `evidence` | Nonempty array stating what is known. |
| `resolving_check` | One exact check that would decide the concern. |
| `owner_stage` | Stage that can perform that check. |

Every `UNKNOWN` check requires a matching unresolved concern and a nonempty
`next_check`. Do not use an unresolved concern for speculation or a conclusive
defect.

## WIP observations

Each `wip_observations` entry has exactly these keys:

| Key | Contract |
|---|---|
| `observation_id` | Unique identifier from the WIP list in `antipattern-catalog.md`. |
| `note` | Concise non-enforcing observation. |
| `evidence` | Nonempty evidence array. |

WIP observations never change a check, stage, finding, or verdict.
