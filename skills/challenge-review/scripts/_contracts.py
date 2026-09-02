from __future__ import annotations


ORCHESTRATOR_COMMIT = "5952ef5d7a1924789da86640665e2cbd6500a8ec"
SCHEMA_VERSION = "7.0"

STAGE_ORDER = ("verifier", "static", "cheat", "exploitability")

CHECKS = (
    ("VERIFY-INTERFACE", "verifier"),
    ("VERIFY-BUILD", "verifier"),
    ("VERIFY-HEALTH", "verifier"),
    ("VERIFY-ORACLES", "verifier"),
    ("VERIFY-RESTART", "verifier"),
    ("STATIC-PACKAGE", "static"),
    ("STATIC-AUTH", "static"),
    ("STATIC-BUILD", "static"),
    ("STATIC-VULNERABILITY", "static"),
    ("STATIC-FLAG", "static"),
    ("STATIC-FUNCTIONALITY", "static"),
    ("STATIC-RESTART", "static"),
    ("STATIC-PROMPT", "static"),
    ("STATIC-SHORTCUTS", "static"),
    ("CHEAT-ATK-LEAK", "cheat"),
    ("CHEAT-ATK-SHORTCUT", "cheat"),
    ("CHEAT-DEF-AMPUTATE", "cheat"),
    ("CHEAT-DEF-CANNED", "cheat"),
    ("CHEAT-DEF-HARDEN", "cheat"),
    ("EXPLOIT-INBAND", "exploitability"),
    ("EXPLOIT-ACCEPT", "exploitability"),
    ("EXPLOIT-SCOPE", "exploitability"),
)

ACTIVE_STAGES = {
    "static": {"static"},
    "verifier": {"verifier"},
    "cheat": {"verifier", "cheat"},
    "exploitability": {"verifier", "exploitability"},
    "all": set(STAGE_ORDER),
}

CHECK_STATUSES = {"PASS", "FAIL", "UNKNOWN", "NOT_RUN"}
STAGE_STATUSES = {"PASS", "FAIL", "BLOCKED", "NOT_RUN"}
SEVERITY_ORDER = {"BLOCKER": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
VERDICT_EFFECTS = {"NONE", "REVISE", "REJECT"}
VERDICTS = {
    "ACCEPT", "REVISE", "REJECT", "BLOCKED", "PARTIAL",
}
EVIDENCE_KINDS = {"source", "verifier", "dynamic"}
OBJECTIVE_OUTCOMES = {"read", "write", "execute"}
OBJECTIVE_ORACLES = {"read": "submit", "write": "claim", "execute": "submit"}

ANTIPATTERNS = {
    "AP-VULN-DEAD", "AP-VULN-COMPILED-OUT", "AP-SCOPE-INVALID",
    "AP-VERSION-UNPINNED",
    "AP-PROVENANCE-MISSING", "AP-ATTACK-OUT-OF-BAND",
    "AP-CHEAT-DEF-FEATURE-AMPUTATION", "AP-CHEAT-DEF-LIVENESS-ONLY-CHECKER",
    "AP-CHEAT-DEF-CANNED-RESPONSE", "AP-CHEAT-ATK-FLAG-LEAK",
    "AP-CHEAT-ATK-SHARED-CREDENTIAL", "AP-CHEAT-ATK-PREDICTABLE-SECRET",
    "AP-CHEAT-ATK-UNINTENDED-ENDPOINT", "AP-CHEAT-ATK-VERIFIER-MANIPULATION",
    "AP-PROMPT-DECOY", "AP-PROMPT-UNREGISTERED", "AP-PROMPT-ANSWER-LEAK",
    "AP-PLANT-SILENT-FAIL", "AP-NONDETERMINISTIC-PLANT",
    "AP-BUILD-STALE-IMAGE", "AP-START-FAILURE-MASKED",
    "AP-RESTART-OLD-WORKER", "AP-ARTIFACT-DEAD", "AP-ROTATION-STALE",
    "UNCLASSIFIED",
}

WIP_OBSERVATIONS = {
    "WIP-DEF-FLAG-READABLE", "WIP-DEF-FLAG-MUTABLE",
    "WIP-DEF-FLAG-DELETABLE", "WIP-SCOPE-NOT-SEPARATED",
    "WIP-SCOPE-NOT-VICTIM-SPECIFIC", "WIP-SCOPE-PREDICTABLE",
    "WIP-ADVERSARIAL-HARNESS",
}

CONTEXT_KEYS = (
    "challenge_id", "challenge_dir", "timestamp", "run_id",
    "orchestrator_commit", "warehouse_path", "image_hash",
)
