"""Historical graph damage cannot mask a cycle through the proposed node. Refs #271."""

import json

import pytest

from blockwart.domain.decisions import DecisionIntegrityError, validate_decision_integrity
from blockwart.domain.runbooks import RunbookIntegrityError, validate_runbook_integrity


@pytest.mark.parametrize(
    ("kind", "validate", "error"),
    [
        ("decision", validate_decision_integrity, DecisionIntegrityError),
        ("runbook", validate_runbook_integrity, RunbookIntegrityError),
    ],
)
@pytest.mark.parametrize("reverse_rows", [False, True])
@pytest.mark.parametrize("direction", ["superseded_by", "supersedes"])
def test_projected_cycle_is_not_masked_by_historical_cycle(
    kind, validate, error, reverse_rows, direction
):
    def row(name, target):
        return {
            "id": name,
            "kind": kind,
            "data_json": json.dumps({"superseded_by": f"{kind}:{target}"}),
        }

    rows = [row("legacy-a", "legacy-b"), row("legacy-b", "legacy-a")]
    if direction == "superseded_by":
        rows.append(row("new-y", "new-x"))
        candidate = {"superseded_by": f"{kind}:new-y"}
    else:
        rows.append(row("new-x", "new-y"))  # Current projected record is ignored.
        rows.append(row("new-y", "new-z"))
        candidate = {"superseded_by": f"{kind}:new-y", "supersedes": [f"{kind}:new-z"]}
    if reverse_rows:
        rows.reverse()
    with pytest.raises(error, match="would create a cycle"):
        validate(rows, object_id="new-x", data=candidate)


@pytest.mark.parametrize(
    ("kind", "validate"),
    [
        ("decision", validate_decision_integrity),
        ("runbook", validate_runbook_integrity),
    ],
)
def test_reachable_historical_cycle_without_return_path_does_not_block(kind, validate):
    rows = [
        {
            "id": "legacy-a",
            "kind": kind,
            "data_json": json.dumps({"superseded_by": f"{kind}:legacy-b"}),
        },
        {
            "id": "legacy-b",
            "kind": kind,
            "data_json": json.dumps({"superseded_by": f"{kind}:legacy-a"}),
        },
    ]
    validate(rows, object_id="new-x", data={"superseded_by": f"{kind}:legacy-a"})
    validate(rows, object_id="new-x", data={})
