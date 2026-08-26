# Access Requests And Temporary Grants

Issue #100 adds a governed way for authenticated principals to request missing
read access instead of arranging it outside Blockwart.

## Workflow

1. A principal that can already `discover` an object may apply for exactly
   **Viewer on `self`**, temporary or permanent, with an optional bounded
   purpose text (untrusted input: length-capped at 500 characters,
   control characters stripped).
2. Principals that currently hold `manage_access` on the target object see the
   pending request in the UI (`/access-requests`), the REST API
   (`GET /api/v1/access-requests`) and MCP
   (`blockwart.list_pending_access_requests`) and approve or deny it.
3. Approval atomically creates exactly one Viewer grant plus audit events
   (`grant_create`, `access_request_approve`). Denial and cancellation create
   no grant. Parallel decisions serialize on a guarded status claim: exactly
   one decision wins, concurrent callers get `409`.
4. Approvers may shorten but never extend a temporary window. A permanent
   request may be shortened to temporary.

The same request, decision, policy and audit contract backs UI, REST API and
MCP; MCP tools proxy the identical REST endpoints.

## Durations And Expiry

- Conservative defaults (module constants in
  `blockwart.services.access_requests`, changed only by shipping code):
  temporary TTL between **5 minutes and 30 days**; at most **10 open
  requests per requester**.
- Temporary grants carry an `expires_at`. The expiry is enforced **in the
  request path**: policy computation ignores expired grants, so access ends at
  the timestamp without a restart and without a cache to invalidate. The
  policy fingerprint changes, which invalidates cursors bound to it.
- Expired approved requests are marked `expired` lazily whenever their status
  is read; the audit trail records `access_request_expire`.
- Permanent grants behave like every other grant and end only through the
  normal revocation lifecycle.

## Notifications

Notifications are outbound hints through one pluggable adapter
(`blockwart.services.access_notifications`). The default adapter sends
nothing. A webhook adapter POSTs a minimal payload — request id, object id,
status, and a stable reference to the authenticated decision surface — never
the untrusted reason text, credentials, or hidden object details.

Notification failures change nothing: attempts are recorded on the request row
(`notification_attempts`, capped at 3), outcomes are visible as
`delivered`/`failed`, and neither request status nor grants depend on them. A
notification can point at a decision; it can never be one.

## Fail-Closed Properties

- Without `discover`, creating, listing and deciding are indistinguishable
  from an unknown object (`404`): no existence leaks.
- Approver authorization is re-evaluated against current policy at decision
  time. Grant revocation, principal deactivation, or losing `manage_access`
  immediately removes queue visibility and decision rights.
- Duplicate retries map onto the single open-request slot per requester,
  object, role and scope (partial unique index), so retries and races cannot
  queue duplicates.

## Audit And Recovery

Audit actions: `access_request_create`, `access_request_approve`,
`access_request_deny`, `access_request_cancel`, `access_request_expire`, plus
the existing `grant_create` for the resulting grant. Entries contain ids and
timestamps, no secrets and no reason text lengths beyond a count.

Manual recovery: revoke the generated grant through the normal grant
management surface (`DELETE /api/v1/objects/{id}/access/grants/{grant_id}`);
completed request rows are historical evidence and need no cleanup. To roll
back the feature, use migration `20260826_0022` downgrade after exporting the
audit trail.
