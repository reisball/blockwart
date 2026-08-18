# Public Release Readiness

This document defines the gate for changing the canonical GitHub repository
from private to public. A successful code review or CI run does not itself
authorize that visibility change.

## Maintained tree

- The maintained tree contains no live credentials or private catalog export.
- Example infrastructure uses reserved domains, documentation IP ranges,
  locally administered example MAC addresses, and generic operator names.
- The repository declares Apache-2.0 licensing and public contribution and
  vulnerability-reporting paths.
- GitHub Actions use least-privilege permissions and immutable action SHAs.
- Secret scanning has no unexplained finding.

## Existing repository history

Changing visibility exposes every reachable branch and tag, retained Actions
history and logs, issues, pull requests, comments, attachments, commit author
metadata, and historical versions of files. Before the visibility change,
record an explicit decision for each of those classes. Do not imply that a
clean current tree removes historical content.

History rewriting, branch deletion, issue/comment editing, Actions-run or
artifact deletion, credential rotation, and repository visibility changes are
separate operations. Each needs its own reviewed scope, recovery plan, and
authorization.

## Known retained disclosures

Unless they are separately removed or rewritten, publication intentionally
retains historical technical context such as old host and service names,
private-network addresses, local workspace paths, and UI screenshots. These
may occur in commits, branches, issues, comments, attachments, or Actions
logs. Treat that context as an explicit disclosure decision, not as content
cleaned by this change.

A point-in-time scan without credential or private-key findings reduces risk;
it is not a guarantee and must be repeated on the exact commit immediately
before publication.

## GitHub settings gate

Immediately before publication, verify the exact repository owner, default
branch and commit, configure branch protection or a ruleset, enable private
vulnerability reporting, review fork pull-request and Actions permissions,
and require the exact-head CI proof. Repeat the repository and history secret
scan after the final push and before changing visibility.
