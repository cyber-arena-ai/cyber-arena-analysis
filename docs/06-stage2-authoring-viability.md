# Stage 2 authoring viability

**Status:** Light hardening needed.

Stage 2 already evaluates application fit and a candidate scenario, but it can
still promote vulnerabilities whose prerequisites are artificial or whose
complete workflow is too shallow to justify expensive runtime study.

Before returning `promising`, require a concise explanation that prerequisite
state arises naturally and that the affected feature belongs to a meaningful
workflow defenders must preserve. Patch size alone is not a rejection reason;
unsupported cases are `uncertain`, and inherently weak scenarios are
`low_potential`.
