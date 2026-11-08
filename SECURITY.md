# Security policy

Applications built on this crate parse search queries typed by their users,
and run them over events collected from systems they do not control. Bugs in
parsing or matching (panics, stack overflows, unbounded memory or CPU use,
or a filter that matches something other than what it says) are security
issues.

## Reporting a vulnerability

Please report privately through
[GitHub security advisories](https://github.com/u-siem/query/security/advisories/new),
not in a public issue. Include the version or commit, and if you can, the
query text and event, or a test, that reproduces the problem.

You should get an answer within a week. Once a fix is released, the advisory
is published and credited to you unless you prefer otherwise.

## Supported versions

Before 1.0, only the latest release gets fixes.
