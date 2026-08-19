# Facility image interface skew

**Status:** Deferred until the orchestration build and release flow stabilizes.

Mutable facility base images can contain an older `challenges.interface` than
the orchestration checkout, causing runtime import failures despite valid
challenge code.

Do not implement this during the current curation work. First stabilize how
orchestration builds and releases facility images. If that final flow builds the
facility services and interfaces together and consumes immutable image digests,
close this issue. If it continues to reuse mutable local tags, fingerprint the
facility Dockerfiles, service code, interface, and registry loader; store the
value as an image label; and reuse an image only when the inspected label
matches. Keep an import smoke test before game startup.
