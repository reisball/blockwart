# Geprüftes Knowledge-Apply und Rollback

`blockwart-knowledge-apply` ist der offline ausgeführte, ausdrücklich
schreibende Begleiter des schreibfreien Befehls
[`blockwart-knowledge-plan`](knowledge-planning.md). Der Planner erhält keinen
Apply-Schalter; HTTP, UI, MCP und der laufende Dienst stellen diese Funktion
nicht bereit. Phase B unterstützt persistente SQLite-Kataloge, weil dafür das
verlangte lokale Backup atomar erstellt und geprüft werden kann. Andere
Datenbank-Backends werden vor dem Öffnen einer schreibfähigen Verbindung
geschlossen abgewiesen.

Der Aufrufer muss die drei unabhängig aufbewahrten Digests eines
`apply_ready=true`-Plans angeben: Klassifikation, Ziel-Snapshot und Plan. Apply
lädt Manifest und bereinigten Snapshot neu, prüft das geschlossene
Quellen-Bundle, Implementierungs-Commit und -Tree sowie alle Schema- und
Planner-Versionen und baut exakt den Phase-A-Plan erneut. Jede Abweichung endet
vor Backup und Transaktion.

Die schreibfreie Vorprüfung vergleicht IDs, Arten, Revisionen, kanonischen
Zustand und alle Relationship-Nachweise mit der aktuellen Datenbank. Sie weist
veraltete Revisionen, Manual-Override-Drift, fehlende Provenienz oder
Relationship-Evidenz, Konflikte, unsichere beziehungsweise ACL-förmige Inhalte
und wiederverwendete Quell-Einträge ab. Berechtigungen werden aus dem aktuellen
Principal- und Grant-Zustand berechnet. Bestehende Objekte und beide Endpunkte
einer neuen Relationship benötigen `discover` und `write`; neue Runbooks,
Decisions oder Projects erfordern zusätzlich einen aktiven globalen Catalog
Owner. Alle Ablehnungen verwenden denselben verdeckenden Fehler.

Nur Runbook, Decision und Project dürfen neu angelegt werden. Bei bestehenden
Assets dürfen ausschließlich ausdrücklich zugeordnete `data.*`-Felder bei
unveränderter Provenienz aktualisiert werden. Geheimnisse, ACL-Daten, Autoren,
Quell-Zeitstempel und Kommentare werden niemals importiert. Die normalen
kanonischen Objekt-, Provenienz-, Referenz- und Relationship-Prüfungen bleiben
vollständig aktiv.

Vor der Mutation erzeugt Apply ein SQLite-Online-Backup in einem vom Aufrufer
geschützten Verzeichnis. Datenbank und Fremdschlüssel, vollständiger logischer
Digest sowie das gepaarte Receipt werden geprüft; Backup und Receipt erhalten
Modus `0400`. Unter der Schreibsperre werden Zustand und Berechtigung erneut
validiert. Eine einzige Transaktion führt optimistische Änderungen aus, prüft
die erwarteten Deltas, Owner-Abdeckung, Kommentar-Neutralität und Integrität
und schreibt genau einen begrenzten Audit-Eintrag. Dieser enthält nur Digests,
Anzahlen, IDs und typisierte Relationship-Identitäten. Eine Identität enthält
Endpunkt-Referenzen und Relationship-Typ sowie einen domänengetrennten Digest
der kanonischen Metadaten; Metadaten, Feldwerte und Dokumenttexte selbst
werden nie aufgenommen.

Ein identischer zweiter Apply prüft den dauerhaften Batch-Nachweis und den
aktuellen Post-State-Digest und liefert ohne Backup, Transaktion oder Audit
`changed=false` und `replayed=true`. Die Wiederverwendung derselben stabilen
`source_id/entry_id` unter einem anderen Plan wird abgewiesen.

Rollback ist ein eigener Unterbefehl. Er verlangt Receipt-Digest, Plan-Digest,
Post-State-Digest und den von Apply gelieferten vollständigen
Datenbank-Digest. Receipt, schreibgeschütztes Backup, Backup-Integrität,
aktueller Catalog Owner, Apply-Nachweis und Live-Zustand werden erneut geprüft.
Jede zwischenzeitliche Katalog- oder Audit-Änderung blockiert den Rollback.
Die Wiederherstellung erfolgt niemals direkt in der aktiven Datei. Das
geschützte Backup wird in eine private Kandidaten-Datenbank im selben
Verzeichnis kopiert; dort werden Rollback-Audit, Integrität und alle logischen
Digests geprüft und die Datei synchronisiert. Erst nach einer erneuten
bytegenauen Drift-Prüfung ersetzt ein atomares Umbenennen die aktive
Datenbank. Der Entwicklungs-Katalog wird vollständig ersetzt; spätere Daten
werden weder zusammengeführt noch erhalten. Fehler vor diesem Austausch
lassen die aktive Datei unverändert. CLI-Fehler melden die Grenze eindeutig
als `database_replaced=false` beziehungsweise nach einem Austausch als
`database_replaced=true`. Ein zweiter Rollback scheitert, weil im
wiederhergestellten Zustand kein Apply-Nachweis mehr vorhanden ist.

Die vollständigen Befehlsbeispiele und maschinenlesbaren Schema-Aufrufe stehen
in der [englischen Vertragsdokumentation](knowledge-apply.md). Automatisches
Data-Routing, Quelldatei-Löschung, Deployment, Runtime-Zugriff,
Credential-Auflösung und Remote-Schreibzugriffe bleiben ausdrücklich außerhalb
dieses Workflows.
