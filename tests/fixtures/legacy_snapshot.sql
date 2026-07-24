INSERT INTO catalog_objects
    (id, kind, label, status, summary, data_json, created_at, updated_at)
VALUES
    (
        'legacy-host',
        'host',
        'Legacy Host',
        'active',
        'Frozen host row.',
        '{"schema_version":1,"hardware":{"cpu":{"cores":8}}}',
        '2025-01-02 03:04:05',
        '2025-02-03 04:05:06'
    ),
    (
        'legacy-system',
        'system',
        'Legacy System',
        'inactive',
        'Frozen system row.',
        '{"schema_version":1,"future_field":{"keep":true},"tags":["legacy","future"]}',
        '2025-03-04 05:06:07',
        '2025-04-05 06:07:08'
    ),
    (
        'legacy-network',
        'netzwerk',
        'Legacy Network',
        'active',
        NULL,
        '{"schema_version":1,"network":{"addresses":[{"ip":"192.0.2.10"}]}}',
        '2025-05-06 07:08:09',
        '2025-06-07 08:09:10'
    ),
    (
        'legacy-service',
        'service',
        'Legacy Service',
        'active',
        'Frozen service row.',
        '{"schema_version":1,"system_id":"system:legacy-system"}',
        '2025-07-08 09:10:11',
        '2025-08-09 10:11:12'
    ),
    (
        'legacy-credential',
        'credential_reference',
        'Legacy Credential Reference',
        'active',
        'Reference only.',
        '{"schema_version":1,"provider":"external","reference":{"name":"legacy"}}',
        '2025-09-10 11:12:13',
        '2025-10-11 12:13:14'
    ),
    (
        'legacy-runbook',
        'runbook',
        'Legacy Runbook',
        'active',
        NULL,
        '{"schema_version":1,"risk_level":"read-only","steps":["inspect"]}',
        '2025-11-12 13:14:15',
        '2025-12-13 14:15:16'
    ),
    (
        'legacy-decision',
        'decision',
        'Legacy Decision',
        'active',
        'Frozen decision row.',
        '{"schema_version":1,"decision":"preserve"}',
        '2026-01-14 15:16:17',
        '2026-02-15 16:17:18'
    ),
    (
        'legacy-project',
        'project',
        'Legacy Project',
        'active',
        'Frozen project row.',
        '{"schema_version":1,"phase":"pilot"}',
        '2026-03-16 17:18:19',
        '2026-04-17 18:19:20'
    );

INSERT INTO relationships (id, from_ref, relation_type, to_ref)
VALUES
    (41, 'system:legacy-system', 'hosts', 'service:legacy-service'),
    (42, 'project:legacy-project', 'documents', 'decision:legacy-decision');

INSERT INTO audit_events (id, object_id, action, actor, summary, created_at)
VALUES
    (
        51,
        'legacy-system',
        'create',
        'legacy-import',
        'Frozen system audit.',
        '2025-04-05 06:07:09'
    ),
    (
        52,
        NULL,
        'import',
        'legacy-import',
        'Frozen global audit.',
        '2026-04-17 18:19:21'
    );
