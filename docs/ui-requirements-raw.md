# Blockwart UI Requirements - Raw Notes

Raw voice notes from Kai. Keep this section as source material first; derive structured requirements and acceptance criteria only after the capture pass.

## 2026-05-17 - Main View Layout Toggle

- "Okay, auf der Hauptansicht, das mit den 1, 2, 3, das gefällt mir schon ganz gut, aber anstatt der 1, 2, 3 hätte ich dir kleine Grafiken. Also ein Block, dann zwei kleine Bröcke und dann drei kleine Blöcke, dass man sieht, wie das dann aussieht."

## 2026-05-17 - Card Click Detail Preview

- "Wenn ich in der Hauptansicht, in der Einser-Ansicht, als auch in der Zweier- oder in der Dreier-Ansicht auf einen Block drauf drücke, dann sehe ich ja momentan, wenn es eine gibt, die Beziehung zu einem Service oder zu einem Host. Ich möchte, dass, wenn ich da drauf klicke, zum einen eine Kurzansicht der Detail-Information des jeweiligen Services oder was auch immer ich draufgeklickt habe und darunter die jetzige Ansicht mit der Beziehung, falls es eine gibt."
- Correction: "Korrektur bei Rohpunkt 2, das soll nur dann eintreten, wenn keine Beziehung vorhanden ist. Also, wenn irgendeiner der Blöcke keine Beziehung hat, dann soll die Detailansicht von dem eigenen Block angezeigt werden. alles andere soll so bleiben"

## 2026-05-17 - Service Name Field

- "Wenn es ein Service ist, dann gibt es dort kein Host-Namenfeld, sondern nur ein Namefeld. Das wird dann praktisch der Service-Name. Wenn ich den Typ Service auswähle, dann wird, wenn es ein bereits existierendes Feld gab, was den Namen beinhaltet, in Service-Name umbenannt."

## 2026-05-17 - Relationship Display Order

- "Wenn ich in der Hauptansicht auf ein System klicke, zum Beispiel Friday, dann werden die Beziehungen soweit korrekt dargestellt. Ich sehe, Typ System Friday bezieht sich zu Typ Service und Typ Host bezieht sich zu Typ System. Ich möchte gerne, dass das in der richtigen Reihenfolge dargestellt wird. Also immer der Typ Host, wenn einer vorhanden ist, soll da oben stehen. Der bezieht sich dann zu dem Typ System, also das System, was ich mir gerade anschaue. Und dann in der zweiten Reihe das Typ System, das, was ich mir gerade anschaue, bezieht sich zu dem Typ Service. Einfach, dass das logisch korrekt dargestellt wird."

## 2026-05-17 - Always Show Applicable Panels And Add Rows

- "Wenn ich derzeit auf einen Service zugreife, zum Beispiel Blockwart, dann stehen da schon Einträge für Netzwerk, für Zugriff, für Relationship. Die kann ich dann auch editieren. Wenn ich aber zu einem Eintrag hingehe, wo kein Netzwerkeintrag vorhanden ist oder kein Zugriff-Eintrag, dann werden die Panels gar nicht angezeigt und ich kann gar keinen hinzufügen. Also, wir müssen jetzt dafür sorgen, dass überall alle Panels angezeigt werden für die jeweilige Condition, also wenn es ein Service ist, die jeweiligen Felder, die es für den Service gibt, wenn es ein Host ist, die jeweiligen Felder für einen Host mit den richtigen Namen, wenn es ein VM ist, bla bla bla. Also alle Panels anzeigen, auch wenn gar dort kein Eintrag vorhanden ist und bei allen Panels da wo sinnvoll auch ein Add-Button hinzuzufügen. Also nicht nur Edit, der bestehende Einträge ändert, sondern wenn ich auf Edit drücke, dann soll ein Add-Button auftauchen. Dann drücke ich da drauf und dann wird eine neue leere Zeile hinzugefügt. Die fülle ich dann aus und dann kann ich sagen Save oder Cancel. Die Eingaben werden natürlich auch geprüft, ob die entsprechend der Felder valide sind, bzw. gibt es Felder, die Pflicht sind oder vielleicht auch Felder, die optional sind, je nachdem."
- Clarification: "Bei Rohpunkt 5 sollen für die jeweiligen Typen die Panels sichtbar sein. Nicht bei Service die Service Panels, bei Host die Host Panels. Sondern jetzt zum Beispiel bin ich beim Blockwart. Da sehe ich den Überblick, Netzwerk, Zugriff. Weil dort auch jeweils Einträge drin sind. Wenn ich jetzt aber auf einen Service klicke, der keine Einträge hat, für irgendwelche dieser Gegenden, dann sehe ich auch nicht die Einträge dazu oder die Panels, um einen Eintrag überhaupt hinzufügen zu können. Ich hoffe, das ist verständlich."

## 2026-05-17 - Configurable Type Field Schema

- "Okay, jetzt möchte ich, dass wir das Schema für die Datenbank überdenken bzw. gerade ziehen und gleichzeitig auch in der UI vom Blockwart in einer eigenen Seite konfigurierbar machen. Und zwar auf Basis des Typs. Also oben links ein Dropdown, wo ich den Typ auswählen kann, die es momentan gibt. Und dann im unteren Bereich sollen alle Felder für diesen Typ auftauchen. Und ich möchte die Felder editierbar machen. Also im Sinne von Feld hinzufügen, Feld löschen, sowas."
