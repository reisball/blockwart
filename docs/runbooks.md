# Canonical Runbooks / Kanonische Runbooks

## English contract

A Blockwart Runbook is the reviewed current truth for an operating or recovery
procedure. It is a knowledge object, never an executor. Blockwart stores and
returns command text exactly as supplied, but never invokes a shell, expands a
placeholder, resolves a credential, retrieves a URL, deploys anything, or
otherwise performs a Runbook step.

`blockwart.domain.object_schema` is the single field, rule, and public-error
source used by UI creation/editing, REST/API v1, Agent API, MCP, OpenAPI,
seed/import validation, search/context, and `blockwart.describe_schema`. The
closed `runbook_status` vocabulary is `draft`, `approved`, `active`,
`deprecated`, `superseded`, and `retired`. The existing closed `risk_level`
vocabulary is `read-only`, `safe-change`, `disruptive`, and `destructive`.
Runbooks never receive asset `lifecycle` or `health` defaults.

| Field | Contract |
|---|---|
| `purpose` | Bounded intent of the procedure |
| `in_scope`, `out_of_scope` | Ordered explicit scope statements |
| `risk_level` | Closed risk classification |
| `approval_required` | Required boolean |
| `approval_requirement` | Bounded approval description; never credential material |
| `prerequisites` | Ordered closed entries with stable unique `id` and `description` |
| `steps` | Ordered closed entries with stable unique `id`, nonblank `title` or `description`, optional exact inert `command`, and separate required `expected_effect` |
| `verification` | Ordered entries with stable unique `id`, `description`, and explicit `success_expectation` |
| `rollback` | Ordered change-reversal instructions using the step shape |
| `recovery` | Ordered safe/healthy-state restoration instructions using the step shape |
| `change_fallback` | `rollback`, `recovery`, or `no_rollback` |
| `change_fallback_rationale` | Required for `recovery` and `no_rollback` |
| `applies_to` | Existing readable `host`, `system`, `network`, `device`, or `service` references |
| `credential_references` | Existing readable `credential_reference` IDs only, never values |
| `related_decisions`, `related_projects`, `related_runbooks` | Existing readable typed knowledge references |
| `supersedes`, `superseded_by` | Existing Runbook references in an acyclic supersession graph |
| `sources` | Safe structured HTTP(S) references; no fetching or full-text import |
| `last_verified_at`, `review_after` | RFC 3339 review timestamps; review cannot precede verification |

Approved and active Runbooks require purpose, risk, nonempty prerequisites,
steps and verification, plus `last_verified_at`. Disruptive or destructive
Runbooks require approval with an approval description and nonempty rollback or
recovery. Every change Runbook (`safe-change`, `disruptive`, or `destructive`)
selects a machine-readable fallback. `rollback` requires rollback instructions;
`recovery` requires recovery instructions and a rationale; `no_rollback`
requires a rationale and is forbidden for disruptive/destructive work.
Deprecated Runbooks require a rationale or visible successor recommendation;
superseded Runbooks require `superseded_by`. Self-links and cycles fail before
any write is committed.

Service Runbook readiness uses a separate explicit service field:
`data.criticality` is the closed `standard`/`critical` vocabulary, with a
missing value interpreted as `standard` for backward compatibility. An active
critical service is ready when at least one READ-authorized, schema-valid
`approved` or `active` Runbook names it in `applies_to`, or an authorized
`documents` relationship connects that Runbook to the service. Names, prose,
tags, health, monitoring state, concealed Runbooks, and draft/deprecated/
superseded/retired Runbooks never imply readiness.

Rollback and recovery are deliberately different. Rollback reverses a change.
Recovery restores a safe or healthy state when reversal alone is insufficient.
Expected effect describes what one instruction should change; verification is
a separate observed check with a success expectation.

All typed targets must exist, match the asserted kind, and be readable by the
writer. Missing, wrong-kind, and concealed targets return the same safe public
failure. Readers see only relationships they may discover. Discover-only stubs
contain no status, risk, procedure, command, source, credential reference, or
relationship data. Attribute filters require detail access. Authorized search
and context support `runbook_status`, `runbook_risk`, and `related_object`.

Canonical fields are reviewed current truth. Comments are a separate review
and observation chronology. Audit records material field changes without
comment bodies. External documents are sources, not a second Runbook body.
Identical normalized writes do not increment the revision and emit no audit.

### Example 1 — read-only diagnosis

All references below are fictitious. This active procedure has prerequisites,
one inert diagnostic instruction, and an explicit success check.

```json
{
  "schema_version": 1,
  "runbook_status": "active",
  "purpose": "Diagnose a fictitious edge service without changing it.",
  "in_scope": ["Read local service health and recent non-secret status."],
  "out_of_scope": ["Restarting, reconfiguring, or deploying the service."],
  "risk_level": "read-only",
  "approval_required": false,
  "prerequisites": [
    {"id": "read-access", "description": "Confirm approved read access to the service console."}
  ],
  "steps": [
    {
      "id": "inspect-health",
      "title": "Inspect health",
      "description": "Read the local health summary.",
      "command": "service-inspect --target demo-edge --read-only\n",
      "expected_effect": "A local status summary is displayed; service state is unchanged."
    }
  ],
  "verification": [
    {
      "id": "health-result",
      "description": "Review the returned health and timestamp.",
      "success_expectation": "Health is healthy and the observation is current."
    }
  ],
  "applies_to": ["service:demo-edge"],
  "sources": [
    {
      "id": "operator-guide",
      "source_type": "documentation",
      "title": "Fictitious edge-service operator guide",
      "url": "https://docs.example.invalid/edge/diagnosis"
    }
  ],
  "last_verified_at": "2026-08-12T12:00:00Z",
  "review_after": "2026-11-12T12:00:00Z"
}
```

### Example 2 — disruptive service/container change with rollback

```json
{
  "schema_version": 1,
  "runbook_status": "approved",
  "purpose": "Apply a reviewed configuration to a fictitious container service.",
  "in_scope": ["Replace the service configuration and restart the container."],
  "out_of_scope": ["Host upgrades and database changes."],
  "risk_level": "disruptive",
  "approval_required": true,
  "approval_requirement": "A designated reviewer records two-person approval in the change system.",
  "prerequisites": [
    {"id": "window", "description": "Confirm the approved maintenance window."},
    {"id": "snapshot", "description": "Confirm a reviewed configuration snapshot reference exists."}
  ],
  "steps": [
    {
      "id": "restart-demo",
      "title": "Apply configuration and restart",
      "command": "container-tool restart demo-api\n",
      "expected_effect": "The demo-api container restarts with the reviewed configuration."
    }
  ],
  "verification": [
    {
      "id": "health-check",
      "description": "Inspect container and application health.",
      "success_expectation": "The container is running and the application health check is healthy."
    }
  ],
  "rollback": [
    {
      "id": "restore-config",
      "description": "Restore the referenced previous configuration and restart the container.",
      "command": "container-tool restore-config demo-api previous-reviewed\ncontainer-tool restart demo-api\n",
      "expected_effect": "The previous reviewed configuration is active."
    }
  ],
  "change_fallback": "rollback",
  "applies_to": ["system:demo-container", "service:demo-api"],
  "related_decisions": ["decision:demo-change-policy"],
  "last_verified_at": "2026-08-10T09:00:00Z",
  "review_after": "2026-10-10T09:00:00Z"
}
```

### Example 3 — database/migration recovery

The backup is named only by a fictitious credential reference and safe source
metadata; no backup contents or credentials are stored.

```json
{
  "schema_version": 1,
  "runbook_status": "approved",
  "purpose": "Recover the fictitious application database after a failed migration.",
  "in_scope": ["Stop writes, restore the reviewed backup, and verify integrity."],
  "out_of_scope": ["Changing database credentials or inventing missing provenance."],
  "risk_level": "destructive",
  "approval_required": true,
  "approval_requirement": "The incident lead and database reviewer approve the recovery path.",
  "prerequisites": [
    {"id": "stop-writes", "description": "Confirm application writes are stopped."},
    {"id": "backup-reference", "description": "Confirm the reviewed backup reference and checksum are available."}
  ],
  "steps": [
    {
      "id": "assess-migration",
      "description": "Record the failed migration state before recovery.",
      "expected_effect": "The failure state is documented without further database writes."
    }
  ],
  "verification": [
    {
      "id": "integrity",
      "description": "Run the documented integrity checks after restoration.",
      "success_expectation": "Schema revision, checksum, constraints, and application read checks all pass."
    }
  ],
  "recovery": [
    {
      "id": "restore-backup",
      "description": "Restore the reviewed fictitious backup into the isolated recovery database.",
      "command": "database-tool restore --reference demo-backup-20260812 --target demo-recovery\n",
      "expected_effect": "The recovery database contains the reviewed backup state."
    },
    {
      "id": "promote-recovered-state",
      "description": "Promote only after every integrity expectation passes.",
      "expected_effect": "The application uses a verified healthy database state."
    }
  ],
  "change_fallback": "recovery",
  "change_fallback_rationale": "Reversing the migration cannot repair partially written data; restoration is required.",
  "applies_to": ["system:demo-database", "service:demo-database-api"],
  "credential_references": ["credential_reference:demo-backup-access"],
  "related_decisions": ["decision:demo-recovery-policy"],
  "related_projects": ["project:demo-schema-migration"],
  "sources": [
    {
      "id": "backup-catalog",
      "source_type": "original",
      "title": "Fictitious reviewed backup catalog entry",
      "url": "https://backup.example.invalid/catalog/demo-backup-20260812"
    }
  ],
  "last_verified_at": "2026-08-12T16:00:00Z",
  "review_after": "2026-09-12T16:00:00Z"
}
```

## Legacy classification and reviewed apply

Existing free-form Runbook rows remain readable. Any rewrite must satisfy the
canonical contract. `blockwart-db runbooks` is deterministic and read-only by
default. It reports missing/invalid fields, unsafe content, invalid stored JSON,
unknown mapping IDs, stale fingerprints, invalid mappings, canonical-row
conflicts, and projected supersession cycles; it never guesses status, risk,
approval, provenance, commands, rollback, or recovery.

A reviewed version-1 mapping binds each change to the SHA-256 of the exact old
canonical JSON data. `data_patch` is a shallow patch, so every unmentioned
extension remains intact:

```yaml
version: 1
runbooks:
  - object_id: legacy-demo-runbook
    expected_data_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    data_patch:
      runbook_status: draft
      approval_required: false
```

```bash
blockwart-db --mapping runbooks.yaml runbooks
blockwart-db --mapping runbooks.yaml --apply runbooks
```

The dry run prints a stable digest bound to the whole Runbook set and proposed
changes. Apply rechecks that exact state before writing, rejects any diagnostic,
and commits atomically. Successful changes increment only changed revisions and
write `runbook_normalize` audit events carrying the plan digest. Reapplying an
already materialized mapping is an audit-free no-op.

## Deutscher Vertrag

Ein Blockwart-Runbook ist die geprüfte aktuelle Wahrheit für einen Betriebs-
oder Recovery-Ablauf. Es ist ein Wissensobjekt und niemals ein Executor.
Befehlstext wird bytegenau gespeichert und zurückgegeben, aber niemals in einer
Shell ausgeführt; Platzhalter werden nicht expandiert, Zugangsdaten nicht
aufgelöst, URLs nicht abgerufen und Deployments nicht ausgelöst.

Die Statuswerte sind abgeschlossen: `draft`, `approved`, `active`,
`deprecated`, `superseded`, `retired`. Die Risikowerte sind `read-only`,
`safe-change`, `disruptive`, `destructive`. Freigegebene und aktive Runbooks
benötigen Zweck, Risiko, Voraussetzungen, Schritte, Verifikation und
`last_verified_at`. Disruptive/destruktive Abläufe benötigen Freigabe sowie
Rollback oder Recovery. Ein Rollback macht eine Änderung rückgängig; Recovery
stellt einen sicheren oder gesunden Zustand wieder her, wenn Umkehr allein
nicht genügt. Wirkung eines Schritts und Erfolgsprüfung bleiben getrennt.

Die Runbook-Bereitschaft eines Dienstes verwendet das explizite Dienstfeld
`data.criticality` mit den abgeschlossenen Werten `standard` und `critical`;
ein fehlender Wert bedeutet abwärtskompatibel `standard`. Ein aktiver kritischer
Dienst ist bereit, wenn mindestens ein autorisiertes, schemagültiges Runbook im
Status `approved` oder `active` ihn über `applies_to` oder eine autorisierte
`documents`-Beziehung benennt. Namen, Freitext, Tags, Zustand, Monitoring sowie
verborgene oder ungeeignete Runbooks werden nicht als Bereitschaft gedeutet.

Die drei vollständigen Beispiele oben sind zugleich die aktiven deutschen
Vertragsbeispiele:

1. **Nur-Lese-Diagnose:** Voraussetzungen, inerte Diagnose und explizite
   Verifikation; Neustart und Konfigurationsänderung sind außerhalb des Scopes.
2. **Disruptive Service-/Container-Änderung:** dokumentierte Freigabe,
   Gesundheitsprüfung und eigener Rollback auf die vorherige Konfiguration.
3. **Datenbank-/Migrations-Recovery:** fiktive Backup-Referenz ohne Geheimwert,
   Integritätsprüfung und ein vom Rollback klar getrennter Recovery-Pfad.

Referenzziele müssen existieren, zum Typ passen und für die schreibende Person
lesbar sein. Fehlende, falsch typisierte und verborgene Ziele haben denselben
sicheren Fehler. Discover-only-Stubs geben weder Status noch Risiko, Schritte,
Befehle, Quellen, Credential-Referenzen oder Beziehungen preis. Kommentare
bleiben die Review-/Beobachtungschronologie; Audit belegt materielle Änderungen
ohne Kommentartext; externe Dokumente bleiben ausschließlich Quellen.

Bestehende Freitext-Runbooks bleiben lesbar. `blockwart-db runbooks` klassifiziert
standardmäßig deterministisch und schreibfrei. Eine Änderung erfolgt nur mit
geprüftem Version-1-Mapping, exakter SHA-256-Bindung und stabilem Plan-Digest.
Der Apply-Lauf prüft den gesamten Zustand erneut, ist atomar und idempotent,
bewahrt unerwähnte Erweiterungsfelder und rät weder Status, Risiko, Herkunft,
Befehle, Freigabe, Rollback noch Recovery.
