# Security

Report suspected vulnerabilities privately through the repository's GitHub security reporting
channel when enabled, or contact the maintainer through the organization's published contact route.
Do not publish secrets or exploit material in public issues.

This unpublished bootstrap has no native parsing or cluster client. Future native work must treat
input as fallible, preserve source evidence, redact protected values by default and leave I/O and
runtime mutation under explicit caller authorization. Generated configuration must never be applied
implicitly. Repository workflows use read-only credentials and must not execute PR-head validation
policy in a privileged job. Release/publication remains disabled.
