# ADR 0012: Explicit offline renderer selection

Status: Accepted

Refines the no-renderer milestone in ADR 0003. Independent ownership, private evidence,
finite targets, unknown retention and no publication or live-cluster acquisition remain accepted.

## Decision

Keep native rendered YAML/JSON input usable without subprocesses. Add caller-materialized local
Helm charts and Kustomize projects, exact versioned command plans and private generated artifact
trees. Rendering is an explicitly selected official-tool operation; ordinary parsing and generation
never invoke it. Selected standalone and kubectl-bundled Kustomize profiles stay distinct.

The optional Linux implementation requires an explicitly provisioned system-scope broker with
reviewed tool registrations and inherited resource, namespace, image, deadline and cleanup bounds.
The library never installs or starts that service implicitly. Caller refusals are isolated; global
clock, boot and manager failures cannot masquerade as recoverable client refusals. Missing runtime
prerequisites fail explicitly, without unsupervised execution or a competing fallback.

Generated charts, bases and overlays have their own provenance; rendered resources cannot recover
original templates or overlay structure. Artifact selection retains source-local ResourceIds through
the same native output projection, including sorting, namespaces and List flattening.

## Consequences

The interface and code tests do not establish official renderer compatibility, live containment,
cold-cache resource fit or interrupted recovery. Those evidence obligations remain independently
pending until their exact admitted profiles and candidates are executed. There are no product
apply, install/upgrade, package publication, remote dependency, plugin or ambient kubeconfig paths.
