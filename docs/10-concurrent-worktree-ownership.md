# Concurrent worktree ownership

**Status:** Required before parallel scaling.

Multiple agents previously edited different histories, duplicated candidate
work, and produced stale registration pointers.

Use one coordinator to allocate one warehouse worktree and one artifact project
directory to each challenge owner. No two agents may write the same worktree.
Supporting agents return evidence to the owner. Create the orchestration
registration worktree only after the warehouse commit is frozen, and use unique
Docker names for every challenge and review run.
