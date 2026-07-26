from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from blockwart.domain.provenance import (
    CatalogProvenance,
    dump_provenance,
    load_provenance,
    provenance_for_read,
)


def test_provenance_normalizes_rfc3339_and_computes_staleness() -> None:
    provenance = CatalogProvenance(
        source_type="discovery",
        source_ref="cmdb://asset/42",
        observed_at="2026-07-26T20:00:00+02:00",
        verified_at="2026-07-26T18:05:00Z",
        stale_after="2026-07-27T00:00:00Z",
    )

    assert provenance.observed_at == "2026-07-26T18:00:00.000000Z"
    assert provenance_for_read(
        provenance,
        now=datetime(2026, 7, 26, 23, 59, tzinfo=UTC),
    ).is_stale is False
    assert provenance_for_read(
        provenance,
        now=datetime(2026, 7, 27, tzinfo=UTC),
    ).is_stale is True


def test_provenance_rejects_naive_timestamps_and_raw_secrets() -> None:
    with pytest.raises(ValidationError, match="UTC offset"):
        CatalogProvenance(observed_at="2026-07-26T18:00:00")

    unsafe = CatalogProvenance(
        source_type="import",
        source_ref="Bearer abcdefghijklmnopqrstuvwxyz",
    )
    with pytest.raises(ValueError, match="raw secret"):
        dump_provenance(unsafe)


def test_invalid_stored_provenance_falls_back_without_leaking() -> None:
    provenance, valid = load_provenance(
        '{"source_type":"import","source_ref":"Bearer abcdefghijklmnopqrstuvwxyz"}'
    )

    assert valid is False
    assert provenance == CatalogProvenance()
