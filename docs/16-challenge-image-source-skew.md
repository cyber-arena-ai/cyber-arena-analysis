# Challenge image source skew

**Status:** Deferred until the orchestration build and release flow stabilizes.

The vulnerable service, or game image, is built by each challenge package.
Many existing builders trust a mutable `cyberarena/chal-*:v1` tag and skip the
build when that tag already exists, so verification can exercise an older image
than the reviewed warehouse commit.

Do not add this mechanism yet. First stabilize how challenge images are built,
published, and selected. If the final flow builds each accepted warehouse
revision once and review and release consume its immutable digest, close this
issue. If authoring continues to reuse mutable local tags, compute a
deterministic fingerprint from the actual build inputs, platform, and declared
build arguments; store it as an OCI image label; and reuse an image only when
the inspected label matches. Record the resulting image ID with the warehouse
SHA and use that exact image for review.
