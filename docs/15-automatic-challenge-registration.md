# Automatic challenge registration

**Status:** One-time orchestration change required.

Challenge packages are auto-discovered from the warehouse, but prompts still
require a manual `_PROMPT_MODULES` entry. Review also currently uses an
orchestration commit solely to pin the warehouse submodule, creating unnecessary
registration branches and stale pointers.

Resolve the prompt module from the discovered challenge package by convention,
and let verification select an explicit warehouse checkout or commit while
recording its SHA. Keep the checked-in submodule as the default release source,
but do not require an orchestration commit merely to review a new warehouse
commit. Accepted warehouse versions can be advanced separately in release
batches.
