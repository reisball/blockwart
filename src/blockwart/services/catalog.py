import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn, CatalogObjectOut


def list_objects(session: Session) -> list[CatalogObjectOut]:
    statement = select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
    rows = session.scalars(statement).all()
    return [
        CatalogObjectOut(
            id=row.id,
            kind=row.kind,  # type: ignore[arg-type]
            label=row.label,
            status=row.status,
            summary=row.summary,
            data=json.loads(row.data_json),
        )
        for row in rows
    ]


def upsert_object(session: Session, payload: CatalogObjectIn) -> CatalogObjectOut:
    row = session.get(CatalogObject, payload.id)
    data_json = json.dumps(payload.data, sort_keys=True)
    if row is None:
        row = CatalogObject(
            id=payload.id,
            kind=payload.kind,
            label=payload.label,
            status=payload.status,
            summary=payload.summary,
            data_json=data_json,
        )
        session.add(row)
    else:
        row.kind = payload.kind
        row.label = payload.label
        row.status = payload.status
        row.summary = payload.summary
        row.data_json = data_json

    session.commit()
    return CatalogObjectOut(**payload.model_dump())
