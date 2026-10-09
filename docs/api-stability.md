# API stability

The unpublished bootstrap exports no public types or functions. The manifest version is local
package identity. Rustdoc and source form the initial local contract; there is no crates.io baseline
and no registry comparison claiming published compatibility. The gate builds Rustdoc with warnings
denied and packages the same locked source.

Native implementation must define its public source and behavior contracts with independent tests
before advertising support. Pre-1.0 intentional API breaks require an explicit ADR/migration decision.
After the maintainer publishes, add a real published SemVer baseline rather than treating an absent
release as success. KubernetesLens #7 and #15 own that transition.
