# Gitea To GitHub Migration Runbook

This runbook prepares a later, separately authorized migration. It does not authorize a GitHub
write, a Gitea write freeze, an import, or a cutover. Gitea remains canonical, writable, and
recoverable until the complete GitHub import and the exact-SHA GitHub Actions run have been proved.

## Required Inputs And Stop Conditions

Before any cutover window, require all of the following:

- Gitea `main` is the approved final commit, its matching push workflow is green, and no pull
  request is open.
- A fresh export from `scripts/migration/export_gitea.py` validates offline with the original token
  supplied only through stdin and the externally pinned manifest SHA-256. Never commit or copy the
  export outside protected storage.
- The export count reconciliation explains every legitimate difference from the discovery baseline
  of 72 issues, 37 pull requests, 292 comments, 47 labels, and seven assets.
- The bundle resolves the current remote `main` and
  `origin/task-070-drilldown-fix` at export time. Its target refs are `refs/heads/main` and
  `refs/heads/archive/gitea-task-070-drilldown-fix`; never substitute stale SHAs.
- Tree and reachable-history secret scans for both exported refs have no findings. A separate
  privacy review classifies author names/e-mail addresses, LAN addresses, issue text, and
  screenshots for the private target. Any secret or unaccepted privacy finding stops cutover.
- The intended GitHub identity, organization, private repository, permissions, branch defaults,
  and billing/Actions availability are verified using read-only checks before a separately
  authorized write. The destination must be empty.

Stop immediately on a missing/lost external manifest pin, failed validator, count or hash mismatch,
changed Gitea ref/index, open PR, number mismatch, missing asset, unexpected redirect,
authentication/authorization error, scan finding, non-empty GitHub target, insufficient
permissions, or GitHub workflow failure. Do not repair numbering by creating filler items outside
the exported plan.

## Prepare A Protected Snapshot

Use a dedicated protected directory on a trusted host. Set a restrictive parent directory and keep
the token in a secret provider that can write it directly to stdin. Do not put a token in an
argument, environment variable, command transcript, reconciliation file, or shell history.

Create a reconciliation JSON document with keys `issues`, `pull_requests`, `comments`, `labels`,
and `assets`. Each value contains the expected current `count` and a non-empty `explanation` when
that count differs from the baseline. Then run:

```text
<secret-provider-to-stdin> | python scripts/migration/export_gitea.py export \
  --base-url http://gitea.example.invalid:3000 \
  --repository services/blockwart \
  --destination-root exports/github-migration \
  --git-repository . \
  --reconciliation /protected/path/reconciliation.json
```

The tool creates one `exports/github-migration/<UTC>-<main-shortsha>` directory atomically. It
refuses an existing final destination, uses directory mode 0700 and file mode 0600, records the
full API and Git inventory in `manifest.json`, and protects that manifest with
`manifest.sha256`. Snapshot format 2 records semantic-consistency projection version 1 separately
from the exact raw-payload proof. The first pass still archives the complete API objects, diff and
patch bytes, and asset bytes without pruning; the file inventory and externally pinned manifest
digest bind those raw files exactly.

Before sealing, the exporter repeats the indexes, every issue/PR subresource, diff/patch
availability check, and asset download. It compares both passes through explicit endpoint-specific
migration projections: unordered label, assignee, asset, file, review, and status collections are
sorted only by stable identities, while PR commit order remains significant. Reviewed display or
computed metadata such as `mergeable` and embedded user activity may drift without invalidating a
capture; `mergeable` remains present in the raw `pull.json` but is not copied into the derived
number plan. Unknown API fields stop the export until they are explicitly classified instead of
being silently discarded.

Counts, identities, migration content and timestamps, parent associations, endpoint availability,
refs, PR state/base/head/merge data, diff/patch bytes, and asset identities/associations/bytes remain
fail-closed. Offline validation reconstructs the same semantic projections from the complete raw
initial capture, verifies its exact raw-payload proof, reconstructs asset bindings, requires the
complete PR evidence schema, and rejects every unmanifested filesystem object. Runtime snapshots
remain ignored and must never be committed.

After the atomic rename, export prints both `export=<path>` and
`manifest_sha256=<64 lowercase hex characters>`. Immediately record that digest in independent,
access-controlled controller custody outside the snapshot directory. The digest is not secret, but
it is the external trust root: do not regenerate or replace the pin from a snapshot presented for
later validation. `manifest.sha256` remains useful for internal corruption detection only and is
not a substitute for the independently held pin. Losing the pin, observing a mismatch, or finding
that the pin was stored only inside the snapshot is a hard stop requiring a new authorized export.

Validate again without network access, still passing the exact original token through stdin and
the independently held original digest:

```text
<secret-provider-to-stdin> | python scripts/migration/export_gitea.py validate \
  --expected-manifest-sha256 <independently-pinned-manifest-sha256> \
  exports/github-migration/<UTC>-<main-shortsha>
```

Archive the validated directory in protected, access-logged storage. Record its manifest hash,
exact `main` SHA, archive-ref SHA, merge base, reconciliation, and independent-verifier verdict.
Any later Gitea write makes the snapshot only a candidate; repeat the export after the write freeze.

## Secret And Privacy Gate

Run the local-only tree scan with Trivy telemetry disabled by the surrounding environment. Do not
publish raw scanner output because even a finding's context can be sensitive:

```text
trivy fs --scanners secret --exit-code 1 --no-progress .
```

The worktree scan cannot see a secret deleted from a later commit. The following automatable
reachable-history preparation enumerates unique content-bearing objects from exactly the two
migration refs into a 0700 temporary directory, scans them locally, and removes the temporary
copies. Commit objects are included so commit messages are checked as well as file blobs. Inspect
the script before use and retain only a redacted pass/fail summary plus the two resolved ref SHAs:

```bash
HISTORY_SCAN_DIR=$(mktemp -d)
chmod 0700 "$HISTORY_SCAN_DIR"
trap 'find "$HISTORY_SCAN_DIR" -mindepth 1 -delete; rmdir "$HISTORY_SCAN_DIR"' EXIT
git rev-list --objects origin/main origin/task-070-drilldown-fix |
  awk '{print $1}' |
  sort -u |
  while read -r object_id; do
    object_type=$(git cat-file -t "$object_id")
    case "$object_type" in
      blob|commit|tag)
        git cat-file "$object_type" "$object_id" >"$HISTORY_SCAN_DIR/$object_id"
        chmod 0600 "$HISTORY_SCAN_DIR/$object_id"
        ;;
    esac
  done
trivy fs --scanners secret --exit-code 1 --no-progress "$HISTORY_SCAN_DIR"
```

In addition, classify author names and e-mail addresses from `git log`, LAN addresses and personal
data in repository files and issue text, and every exported screenshot/attachment. Record whether
each class is accepted for the initially private GitHub repository. Automation supplements but does
not replace this privacy review. Any unreviewed output or finding is a hard stop.

## Cutover Sequence

After a separate explicit GO, use the shortest practical Gitea write freeze and perform these steps
in order:

1. Recheck identity, organization, target privacy, permissions, open-PR count, final Gitea `main`
   SHA, and the green exact-SHA Gitea push run.
2. Freeze project writes without archiving, deleting, or otherwise weakening the Gitea source.
3. Produce and independently validate a fresh snapshot. Re-run tree/history secret scans and the
   privacy review on both reachable refs. Stop on every finding.
4. Create the empty private GitHub repository only under its separately approved authority.
5. Import the Git bundle as `main` plus only
   `archive/gitea-task-070-drilldown-fix`. Verify the remote object SHAs and their merge base.
6. Create labels, then create every number-plan item strictly in ascending order. Regular issues
   preserve state, labels, author/time attribution in the imported body, comments, and asset links.
   Gitea PRs become closed issues labeled `legacy-pr` with original base/head/merge/status metadata.
   Number 86 is the exported closed tombstone. After every create, compare GitHub's returned number
   with the planned number and stop on the first mismatch.
7. Upload assets from their hashed local files, verify their hashes and access, then apply the
   manifest's UUID-to-file-to-GitHub-URL rewrite mapping. Verify all rewritten links.
8. Reconcile GitHub counts, IDs/numbers, states, labels, comments, assets, refs, hashes, and a sample
   of historical cross-references against the manifest. No unexplained delta is acceptable.
9. Run GitHub Actions on the exact imported `main` SHA. Static workflow parity is not runtime proof;
   require the complete lock, Ruff, compile, Pytest, OpenAPI, wheel, Docker, and container proof.
10. Only after independent verification, designate GitHub canonical and separately decide branch
    protection, secrets, runners, deployment integration, and the future Gitea retention policy.

## Rollback

Before canonical designation, rollback is non-destructive: keep GitHub private and explicitly
non-canonical, end the write freeze, and continue using unchanged Gitea. Preserve the failed import
and logs only if their access controls are adequate; otherwise remove them under separate approval.
Fix the exporter/importer or target configuration, create a new empty private target if numbering
was consumed, and repeat from a fresh Gitea snapshot. Never hide a number error with fillers.

If a defect is found after canonical designation, stop GitHub writes, record both systems' exact
states, and request a separate rollback decision. Do not attempt a reverse sync automatically.
Gitea can be restored as canonical only after proving that it has not lost writes made after the
cutover; otherwise reconcile those writes under an approved data-recovery plan first.

## Evidence To Retain

Retain the accepted commit SHAs, Gitea and GitHub exact-SHA CI run links, externally pinned export
manifest hash in independent custody,
offline-validator output, count reconciliation, bundle ref/hash/merge-base proof, number-by-number
import log, asset rewrite/hash proof, tree/history secret scans, privacy adjudication, identity and
permission checks, independent review, stop/rollback decisions, and canonical-source decision.
Redact secret values; retaining an Authorization header or token as evidence is forbidden.
