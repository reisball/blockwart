import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated, Any
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.domain.object_schema import DEVICE_CATEGORIES
from blockwart.domain.placement import PlacementError
from blockwart.domain.relationships import (
    LINK_KINDS,
    NETWORK_DEVICE_CATEGORIES,
    RELATIONSHIP_TYPES,
    RelationshipIntegrityError,
)
from blockwart.domain.security import find_secret_violations
from blockwart.domain.ui_schema import (
    get_ui_schema,
    schema_field_payload,
    ui_schema_payload,
)
from blockwart.schemas.catalog import (
    ENDPOINT_TYPE_OPTIONS,
    OBJECT_STATUSES,
    PUBLIC_OBJECT_KINDS,
    CatalogObjectIn,
    CatalogObjectOut,
)
from blockwart.services.catalog import get_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    authorize_object_command,
    create_attached_device,
    create_child_object,
    create_object_relationship,
    delete_catalog_object,
    delete_object_relationship,
    revision_etag,
    update_catalog_object,
)
from blockwart.services.grant_management import (
    actor_can_manage_owner_grants,
    create_managed_grant,
    preview_grant_scope,
    query_object_access,
    revoke_managed_grant,
    search_manageable_principals,
    update_managed_grant,
)
from blockwart.services.queries import (
    CatalogBrowseReadModel,
    RelatedRelationshipReadModel,
    object_id_from_ref,
    primary_name_value,
    query_catalog_browse,
    query_catalog_detail,
    query_device_graph,
)
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    read_access_from_request,
    require_browser_read_access,
    require_browser_write_csrf,
)
from blockwart.ui.write_commands import execute_ui_command, ui_write_context

templates = Jinja2Templates(directory=TEMPLATE_DIR)
router = APIRouter(
    tags=["ui"],
    include_in_schema=False,
    dependencies=[Depends(require_browser_read_access)],
)

OBJECT_KINDS = PUBLIC_OBJECT_KINDS
OBJECT_STATUSES_UI = OBJECT_STATUSES
RELATION_TYPES = RELATIONSHIP_TYPES
PLATFORM_TYPES = ("LXC", "VM", "WSL")
SAFE_DATA_JSON_FALLBACK = "{\n  \"schema_version\": 1\n}"
HARDWARE_OBJECT_KINDS = {"host", "system"}
DEVICE_OBJECT_KIND = "device"
ATTACHMENT_RELATION_TYPE = "attached_to"
NETWORK_ADDRESS_EDIT_KINDS = {"host", "system", "network"}
NETWORK_PORT_EDIT_KINDS: set[str] = set()
NETWORK_ENDPOINT_EDIT_KINDS = {"host", "system", "network", "service"}
SERVICE_INFORMATION_OBJECT_KINDS = {"service"}
ENDPOINT_TYPES = ENDPOINT_TYPE_OPTIONS
DEVICE_LINK_KINDS = tuple(sorted(LINK_KINDS))


def _metadata_timestamp(value: str | None, translator: Any) -> str:
    if not value:
        return "-"
    parsed = _parse_timestamp(value)
    if parsed is None:
        return value
    exact = translator(
        "timestamp.exact",
        value=parsed.strftime("%Y-%m-%d %H:%M"),
    )
    return f"{exact} · {_relative_timestamp(parsed, translator)}"


def _parse_timestamp(value: str) -> datetime | None:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _relative_timestamp(value: datetime, translator: Any) -> str:
    now = datetime.now(UTC).replace(tzinfo=None)
    delta_seconds = int((now - value).total_seconds())
    if delta_seconds < 0:
        return translator("timestamp.just_now")
    minute = 60
    hour = 60 * minute
    day = 24 * hour
    if delta_seconds < minute:
        return translator("timestamp.just_now")
    if delta_seconds < hour:
        minutes = delta_seconds // minute
        return translator(
            "timestamp.minute_ago" if minutes == 1 else "timestamp.minutes_ago",
            count=minutes,
        )
    if delta_seconds < day:
        hours = delta_seconds // hour
        return translator(
            "timestamp.hour_ago" if hours == 1 else "timestamp.hours_ago",
            count=hours,
        )
    days = delta_seconds // day
    return translator(
        "timestamp.day_ago" if days == 1 else "timestamp.days_ago",
        count=days,
    )


def _localized_audit_lines(
    event: Mapping[str, Any],
    translator: Any,
) -> list[str]:
    details = event.get("details")
    if not isinstance(details, Mapping):
        return [str(event.get("summary") or event.get("action") or "")]
    action = str(details.get("event") or event.get("action") or "")
    if action == "legacy":
        return [str(details.get("legacy_summary") or event.get("summary") or "")]
    if action == "update":
        changes = details.get("changes")
        lines = (
            [
                _localized_audit_change(change, translator)
                for change in changes
                if isinstance(change, Mapping)
            ]
            if isinstance(changes, list)
            else []
        )
        return lines or [
            translator(
                "audit.update",
                object_ref=str(details.get("object_ref") or ""),
            )
        ]
    template_key = {
        "create": "audit.create",
        "create_attached_device": "audit.create_attached_device",
        "delete": "audit.delete",
        "relationship_create": "audit.relationship_create",
        "relationship_delete": "audit.relationship_delete",
        "relationship_metadata_replace": "audit.relationship_metadata_replace",
        "grant_create": "audit.grant_create",
        "grant_update": "audit.grant_update",
        "grant_revoke": "audit.grant_revoke",
        "placement_assign": "audit.placement_assign",
        "seed_create": "audit.seed_create",
        "seed_update": "audit.seed_update",
        "seed_relationship_create": "audit.seed_relationship_create",
        "seed_skip_manual_override": "audit.seed_skip_manual_override",
        "interface_normalize": "audit.interface_normalize",
        "placement_state_normalize": "audit.placement_state_normalize",
    }.get(action)
    if template_key is None:
        return [str(event.get("summary") or action)]
    values = {
        key: value
        for key, value in details.items()
        if isinstance(value, str | int | float)
    }
    if action in {"grant_create", "grant_update", "grant_revoke"}:
        values["target_principal_id"] = str(
            details.get("target_principal_id")
            or details.get("principal_id")
            or ""
        )
    return [translator(template_key, **values)]


def _localized_audit_change(
    change: Mapping[str, Any],
    translator: Any,
) -> str:
    field = str(change.get("field") or "data")
    field_label = translator(f"audit.field.{field}")
    if field_label == f"audit.field.{field}":
        field_label = field
    if change.get("value_change") is True:
        old_value = str(change.get("old") or translator("audit.empty"))
        new_value = str(change.get("new") or translator("audit.empty"))
        return translator(
            "audit.field_change",
            field=field_label,
            old=old_value,
            new=new_value,
        )
    return translator("audit.field_changed", field=field_label)


def _index_template_context(
    request: Request,
    read_model: CatalogBrowseReadModel,
    *,
    q: str,
    kind: str,
    view: str,
    form: dict[str, str],
    error: str | None,
    show_create_form: bool,
    can_write_enabled: bool,
    form_kind: str | None = None,
    selected_asset_ref_override: str = "",
    detail_mode: bool = False,
    detail_query_string: str = "",
) -> dict[str, Any]:
    current_access = read_access_from_request(request)
    i18n = translation_context(request)
    translator = i18n["t"]
    localized_schemas = _localized_ui_schema_payload(
        str(i18n["locale"]),
        translator,
    )
    selected_form_kind = (
        form_kind
        if form_kind in OBJECT_KINDS
        else str(form.get("kind") or OBJECT_KINDS[0])
    )
    if selected_form_kind not in OBJECT_KINDS:
        selected_form_kind = OBJECT_KINDS[0]
    explorer = read_model.explorer
    normalized_query = q.strip().casefold()
    selected_asset_ref = selected_asset_ref_override or next(
        (
            f"{catalog_object.kind}:{catalog_object.id}"
            for catalog_object in read_model.objects
            if normalized_query
            and normalized_query
            in {
                catalog_object.id.casefold(),
                read_model.display_names[catalog_object.id].casefold(),
            }
        ),
        next(
            (
                f"{catalog_object.kind}:{catalog_object.id}"
                for catalog_object in read_model.objects
            ),
            next(iter(explorer["assets"]), ""),
        ),
    )
    create_parents = [
        target
        for target in read_model.relation_targets
        if Permission.CREATE_CHILD in target.capabilities
    ]
    device_parent_refs = {
        f"{target.kind}:{target.id}"
        for target in create_parents
        if _supports_device_attachment_parent(target)
    }
    return {
        "title": "Blockwart",
        "objects": read_model.objects,
        "q": q,
        "kind": kind,
        "view": view,
        "is_filtered": bool(q or kind),
        "object_kinds": OBJECT_KINDS,
        "object_statuses": OBJECT_STATUSES_UI,
        "platform_types": PLATFORM_TYPES,
        "device_categories": sorted(DEVICE_CATEGORIES),
        "ui_schemas": localized_schemas,
        "form_ui_schema": localized_schemas[selected_form_kind],
        "create_fields_by_key": {
            **{
                str(field["key"]): field
                for schema in localized_schemas.values()
                for field in schema["create_field_definitions"]
            },
            **_fields_by_key(
                localized_schemas[selected_form_kind][
                    "create_field_definitions"
                ]
            ),
        },
        "display_names": read_model.display_names,
        "object_counts": read_model.object_counts,
        "health_counts": read_model.health_counts,
        "total_objects": read_model.total_objects,
        "error": error,
        "form": form,
        "systems": read_model.systems,
        "relation_targets": create_parents,
        "device_parent_refs": device_parent_refs,
        "relation_types": RELATION_TYPES,
        "show_create_form": show_create_form,
        "index_relationships": read_model.index_relationships,
        "explorer": explorer,
        "selected_asset_ref": selected_asset_ref,
        "detail_mode": detail_mode,
        "detail_query_string": detail_query_string
        or urlencode(
            [
                ("view", view),
                ("q", q),
                ("kind", kind),
            ]
        ),
        "unassigned_count": (
            len(explorer["standalone_systems"])
            + len(explorer["standalone_services"])
            + sum(
                len(branch["services"])
                for branch in explorer["standalone_systems"]
            )
        ),
        "can_write": can_write_enabled,
        "can_create": bool(create_parents),
        "is_platform_admin": current_access.principal.is_admin,
        "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
        **i18n,
    }


def _localized_ui_schema_payload(
    locale: str,
    translator: Any,
) -> dict[str, dict[str, Any]]:
    payload = ui_schema_payload()
    for schema in payload.values():
        for collection in ("schema_fields", "create_field_definitions"):
            for field in schema[collection]:
                labels = field.get("localized_labels")
                placeholders = field.get("localized_placeholders")
                field["label"] = (
                    labels.get(locale)
                    if isinstance(labels, dict) and labels.get(locale)
                    else translator(str(field["label_key"]))
                )
                field["placeholder"] = (
                    placeholders.get(locale, "")
                    if isinstance(placeholders, dict) and locale in placeholders
                    else (
                        translator(str(field["placeholder_key"]))
                        if field.get("placeholder_key")
                        else ""
                    )
                )
        primary_field = next(
            field
            for field in schema["schema_fields"]
            if field["key"] == "primary_name"
        )
        schema["primary_name_label"] = primary_field["label"]
        for panel in schema["panels"]:
            panel["label"] = translator(str(panel["label_key"]))
    return payload


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: str = "",
    kind: str = "",
    create: str = "",
    view: str = "catalog",
):
    normalized_kind = kind if kind in OBJECT_KINDS else ""
    selected_view = view if view in {"catalog", "topology"} else "catalog"
    read_model = query_catalog_browse(
        session,
        read_access_from_request(request),
        query=q,
        kind=normalized_kind or None,
    )
    create_enabled = any(
        Permission.CREATE_CHILD in target.capabilities
        for target in read_model.relation_targets
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        context=_index_template_context(
            request,
            read_model,
            q=q,
            kind=normalized_kind,
            view=selected_view,
            form=_empty_form(),
            error=None,
            show_create_form=create_enabled and create == "1",
            can_write_enabled=False,
        ),
    )


@router.get("/settings/schema", response_class=HTMLResponse)
def schema_settings(
    request: Request,
    kind: str = "system",
):
    selected_kind = kind if kind in OBJECT_KINDS else "system"
    return templates.TemplateResponse(
        request,
        "schema_settings.html",
        context=_schema_settings_context(
            request,
            selected_kind=selected_kind,
        ),
    )


def _schema_settings_context(
    request: Request,
    *,
    selected_kind: str,
) -> dict[str, Any]:
    i18n = translation_context(request)
    schemas = _localized_ui_schema_payload(str(i18n["locale"]), i18n["t"])
    schema = schemas[selected_kind]
    schema_fields = list(schema["schema_fields"])
    return {
        "title": i18n["t"]("schema.title"),
        "object_kinds": OBJECT_KINDS,
        "selected_kind": selected_kind,
        "ui_schema": schema,
        "schema_fields": schema_fields,
        "schema_fields_by_key": _fields_by_key(schema_fields),
        "create_fields": list(schema["create_field_definitions"]),
        "ui_schemas": schemas,
        **i18n,
    }


def _detail_template_context(
    request: Request,
    read_model: Any,
    *,
    error: str | None,
    notice: str | None,
    edit_section: str,
    can_write_enabled: bool,
    can_manage_access_enabled: bool,
    can_manage_owner_grants: bool,
    grant_access: Any | None,
    grant_scope_preview: Any | None,
    principal_results: tuple[Any, ...],
    principal_query: str,
    device_graph: Mapping[str, Any] | None = None,
    relationship_form: Mapping[str, Any] | None = None,
    data_json_override: str | None = None,
    form_rows: Mapping[str, list[Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    i18n = translation_context(request)
    translator = i18n["t"]
    catalog_object = read_model.catalog_object
    if catalog_object.visibility == "stub":
        return {
            "title": f"{catalog_object.label} - Blockwart",
            "object": catalog_object,
            "is_stub": True,
            "can_write": False,
            "error": None,
            "notice": None,
            "edit_section": "",
            **i18n,
        }
    object_data = catalog_object.data
    schemas = _localized_ui_schema_payload(str(i18n["locale"]), translator)
    ui_schema = schemas[catalog_object.kind]
    schema_fields = list(ui_schema["schema_fields"])
    access_methods = _display_access_methods(
        catalog_object,
        read_model.relationship_groups,
        read_model.object_map,
    )
    network = _network_summary(object_data)
    hardware = _hardware_summary(object_data)
    hardware_fields = _hardware_schema_fields(schema_fields, hardware)
    device = _device_summary(object_data)
    device_fields = _device_schema_fields(schema_fields, device)
    ports = _list_of_mappings(object_data.get("ports"))
    endpoints = _list_of_mappings(object_data.get("endpoints"))
    service_information = _service_information_summary(object_data)
    service_information_fields = _service_information_schema_fields(
        schema_fields,
        service_information,
    )
    can_edit_network_addresses = catalog_object.kind in NETWORK_ADDRESS_EDIT_KINDS
    can_edit_network_ports = catalog_object.kind in NETWORK_PORT_EDIT_KINDS
    can_edit_network_endpoints = catalog_object.kind in NETWORK_ENDPOINT_EDIT_KINDS
    can_edit_device = catalog_object.kind == DEVICE_OBJECT_KIND
    submitted_rows = form_rows or {}
    submitted_device_rows = submitted_rows.get("device_fields") or []
    if submitted_device_rows:
        submitted_device = submitted_device_rows[0]
        submitted_values = {
            "device_category": str(submitted_device.get("category") or ""),
            "device_manufacturer": str(submitted_device.get("manufacturer") or ""),
            "device_model": str(submitted_device.get("model") or ""),
        }
        for field in device_fields:
            field["value"] = submitted_values.get(field["key"], field["value"])
    network_address_rows = _mapping_rows_override(
        submitted_rows.get("network_addresses"),
        _padded_mappings(
            network["addresses"],
            max(1, len(network["addresses"])),
        ),
    )
    port_rows = _mapping_rows_override(
        submitted_rows.get("network_ports"),
        _padded_mappings(ports, max(1, len(ports))),
    )
    endpoint_rows = _mapping_rows_override(
        submitted_rows.get("network_endpoints"),
        _endpoint_edit_rows(endpoints),
    )
    own_ref = f"{catalog_object.kind}:{catalog_object.id}"
    access_method_rows = [
        row
        for row in _mapping_rows_override(
        submitted_rows.get("access_methods"),
        _access_method_rows(catalog_object, access_methods),
        )
        if str(row.get("source_ref")) == own_ref
    ]
    own_access_method_count = len(_list_of_mappings(object_data.get("access_methods")))
    audit_events = [
        {
            **event,
            "summary_lines": _localized_audit_lines(event, translator),
        }
        for event in read_model.audit_events
    ]
    return {
        "title": f"{catalog_object.label} - Blockwart",
        "object": catalog_object,
        "relationships": read_model.relationships,
        "relationship_groups": read_model.relationship_groups,
        "relationship_targets": read_model.relationship_targets,
        "relation_types": RELATION_TYPES,
        "comment": str(object_data.get("comment") or ""),
        "audit_events": audit_events,
        "ui_schema": ui_schema,
        "schema_fields_by_key": _fields_by_key(schema_fields),
        "primary_name_value": primary_name_value(catalog_object),
        "network": network,
        "hardware": hardware,
        "hardware_fields": hardware_fields,
        "supports_hardware": catalog_object.kind in HARDWARE_OBJECT_KINDS,
        "container": _container_summary(object_data),
        "service_information": service_information,
        "service_information_fields": service_information_fields,
        "supports_service_information": (
            catalog_object.kind in SERVICE_INFORMATION_OBJECT_KINDS
        ),
        "ports": ports,
        "endpoints": endpoints,
        "device": device,
        "device_fields": device_fields,
        "can_edit_device": can_edit_device,
        "device_categories": tuple(sorted(DEVICE_CATEGORIES)),
        "device_chain_rows": _device_chain_rows(device_graph),
        "show_device_chain": bool(
            catalog_object.kind == DEVICE_OBJECT_KIND
            or (device_graph and device_graph.get("edges"))
        ),
        "device_attachment_targets": [
            target
            for target in read_model.relationship_targets
            if _supports_device_attachment_parent(target)
        ],
        "device_link_kinds": DEVICE_LINK_KINDS,
        "relationship_form": dict(relationship_form or {}),
        "network_address_rows": network_address_rows,
        "port_rows": port_rows,
        "endpoint_rows": endpoint_rows,
        "endpoint_types": ENDPOINT_TYPES,
        "can_edit_network_addresses": can_edit_network_addresses,
        "can_edit_network_ports": can_edit_network_ports,
        "can_edit_network_endpoints": can_edit_network_endpoints,
        "can_edit_network": bool(
            can_edit_network_addresses
            or can_edit_network_ports
            or can_edit_network_endpoints
        ),
        "network_has_editable_rows": bool(
            (can_edit_network_addresses and network["addresses"])
            or (can_edit_network_ports and ports)
            or (can_edit_network_endpoints and endpoints)
        ),
        "access_methods": access_methods,
        "access_method_rows": access_method_rows,
        "access_has_rows": bool(access_methods),
        "access_add_row": {
            "type": "",
            "endpoint": "",
            "auth_mode": "",
            "source_kind": catalog_object.kind,
            "source_label": catalog_object.label,
            "source_ref": f"{catalog_object.kind}:{catalog_object.id}",
            "index": own_access_method_count,
        },
        "credential_references": [],
        "data_json": (
            data_json_override
            if data_json_override is not None
            else json.dumps(
                _without_credential_references(catalog_object.data),
                indent=2,
                sort_keys=True,
            )
        ),
        "created_at_display": _metadata_timestamp(
            catalog_object.created_at,
            translator,
        ),
        "updated_at_display": _metadata_timestamp(
            catalog_object.last_changed or catalog_object.updated_at,
            translator,
        ),
        "object_kinds": OBJECT_KINDS,
        "object_statuses": OBJECT_STATUSES_UI,
        "platform_types": PLATFORM_TYPES,
        "error": error,
        "notice": notice,
        "edit_section": edit_section,
        "can_write": can_write_enabled,
        "can_manage_access": can_manage_access_enabled,
        "can_manage_owner_grants": can_manage_owner_grants,
        "grant_access": grant_access,
        "grant_scope_preview": grant_scope_preview,
        "grant_principal_results": principal_results,
        "grant_principal_query": principal_query,
        "grant_roles": tuple(Role),
        "grant_scopes": tuple(GrantScope),
        "can_delete": Permission.DELETE in catalog_object.capabilities,
        "object_etag": revision_etag(catalog_object.revision),
        "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
        **i18n,
    }


def _detail_navigation_context(
    request: Request,
    object_id: str,
) -> dict[str, Any]:
    view_value = request.query_params.get("view", "")
    view = view_value if view_value in {"catalog", "topology"} else "catalog"
    kind_value = request.query_params.get("kind", "")
    kind = kind_value if kind_value in OBJECT_KINDS else ""
    query = request.query_params.get("q", "")[:200]
    state_value = request.query_params.get("return_state", "")
    return_state = (
        state_value
        if re.fullmatch(r"[A-Za-z0-9_-]{12,64}", state_value)
        else ""
    )
    detail_params = [
        ("view", view),
        ("q", query),
        ("kind", kind),
    ]
    if return_state:
        detail_params.append(("return_state", return_state))
    detail_query_string = urlencode(detail_params)
    detail_href = f"/objects/{object_id}?{detail_query_string}"
    return_params = [
        ("view", view),
        ("q", query),
        ("kind", kind),
    ]
    if return_state:
        return_params.append(("restore", return_state))
    return_query_string = urlencode(return_params)
    translator = translation_context(request)["t"]
    edit_sections = (
        "overview",
        "hardware",
        "service-information",
        "device",
        "network",
        "access",
        "permissions",
        "relationship-add",
    )
    return {
        "view": view,
        "q": query,
        "kind": kind,
        "return_state": return_state,
        "detail_query_string": detail_query_string,
        "detail_href": detail_href,
        "detail_edit_hrefs": {
            section: f"{detail_href}&edit={section}"
            for section in edit_sections
        },
        "detail_post_urls": {
            "overview": detail_href,
            "network": f"/objects/{object_id}/network?{detail_query_string}",
            "access": f"/objects/{object_id}/access?{detail_query_string}",
            "grants": (
                f"/objects/{object_id}/permissions/grants?{detail_query_string}"
            ),
            "relationships": (
                f"/objects/{object_id}/relationships?{detail_query_string}"
            ),
            "comment": f"/objects/{object_id}/comment?{detail_query_string}",
        },
        "detail_return_href": f"/?{return_query_string}",
        "detail_back_label": translator(
            "detail.back_topology" if view == "topology" else "detail.back"
        ),
    }


def _render_object_detail(
    request: Request,
    session: Session,
    object_id: str,
    *,
    read_model: Any | None = None,
    error: str | None,
    notice: str | None = None,
    edit_section: str,
    can_write_enabled: bool,
    relationship_form: Mapping[str, Any] | None = None,
    data_json_override: str | None = None,
    form_rows: Mapping[str, list[Mapping[str, Any]]] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    access = read_access_from_request(request)
    detail_read_model = read_model or query_catalog_detail(
        session,
        object_id,
        access,
    )
    if detail_read_model is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    device_graph = query_device_graph(
        session,
        object_id,
        access,
    )
    navigation = _detail_navigation_context(request, object_id)
    browse_read_model = query_catalog_browse(
        session,
        access,
        query=str(navigation["q"]),
        kind=str(navigation["kind"]) or None,
    )
    object_ref = (
        f"{detail_read_model.catalog_object.kind}:"
        f"{detail_read_model.catalog_object.id}"
    )
    if detail_read_model.catalog_object.visibility == "stub":
        can_write_enabled = False
        can_manage_access_enabled = False
        edit_section = ""
    else:
        can_write_enabled = (
            Permission.WRITE
            in detail_read_model.catalog_object.capabilities
        )
        can_manage_access_enabled = (
            Permission.MANAGE_ACCESS
            in detail_read_model.catalog_object.capabilities
        )
        if (
            edit_section == "permissions"
            and not can_manage_access_enabled
        ) or (
            edit_section != "permissions"
            and edit_section
            and not can_write_enabled
        ):
            edit_section = ""
    principal_query = request.query_params.get("principal_q", "")[:100].strip()
    grant_access = None
    grant_scope_preview = None
    principal_results: tuple[Any, ...] = ()
    can_manage_owner_grants = False
    if can_manage_access_enabled:
        grant_context = ui_write_context(request, access)
        grant_access = query_object_access(
            session,
            grant_context,
            object_id=object_id,
        )
        grant_scope_preview = preview_grant_scope(
            session,
            grant_context,
            object_id=object_id,
            scope=GrantScope.SUBTREE,
        )
        can_manage_owner_grants = actor_can_manage_owner_grants(
            grant_context,
            object_id=object_id,
        )
        if len(principal_query) >= 2:
            principal_results = search_manageable_principals(
                session,
                grant_context,
                object_id=object_id,
                query=principal_query,
            )
    context = _index_template_context(
        request,
        browse_read_model,
        q=str(navigation["q"]),
        kind=str(navigation["kind"]),
        view=str(navigation["view"]),
        form=_empty_form(),
        error=None,
        show_create_form=False,
        can_write_enabled=can_write_enabled,
        selected_asset_ref_override=object_ref,
        detail_mode=True,
        detail_query_string=str(navigation["detail_query_string"]),
    )
    context.update(
        _detail_template_context(
            request,
            detail_read_model,
            error=error,
            notice=notice or _relationship_notice(request),
            edit_section=edit_section,
            can_write_enabled=can_write_enabled,
            can_manage_access_enabled=can_manage_access_enabled,
            can_manage_owner_grants=can_manage_owner_grants,
            grant_access=grant_access,
            grant_scope_preview=grant_scope_preview,
            principal_results=principal_results,
            principal_query=principal_query,
            device_graph=device_graph,
            relationship_form=relationship_form,
            data_json_override=data_json_override,
            form_rows=form_rows,
        )
    )
    context.update(navigation)
    context["detail_mode"] = True
    response = templates.TemplateResponse(
        request,
        "index.html",
        context=context,
        status_code=status_code,
    )
    if detail_read_model.catalog_object.visibility == "detail":
        response.headers["ETag"] = revision_etag(
            detail_read_model.catalog_object.revision
        )
    return response


def _detail_redirect_url(request: Request, object_id: str) -> str:
    return str(_detail_navigation_context(request, object_id)["detail_href"])


@router.get("/objects/{object_id}", response_class=HTMLResponse)
def object_detail(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    edit: str = "",
):
    read_model = query_catalog_detail(
        session,
        object_id,
        read_access_from_request(request),
    )
    if read_model is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    write_enabled = (
        read_model.catalog_object.visibility == "detail"
        and Permission.WRITE in read_model.catalog_object.capabilities
    )
    manage_access_enabled = (
        read_model.catalog_object.visibility == "detail"
        and Permission.MANAGE_ACCESS in read_model.catalog_object.capabilities
    )
    edit_allowed = (
        manage_access_enabled
        if edit == "permissions"
        else write_enabled
    )
    return _render_object_detail(
        request,
        session,
        object_id,
        read_model=read_model,
        error=None,
        edit_section=edit if edit_allowed else "",
        can_write_enabled=write_enabled,
    )


@router.post(
    "/objects/{object_id}/permissions/grants",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def create_object_grant_from_ui(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    principal_id: Annotated[str, Form(max_length=36)],
    role: Annotated[str, Form(max_length=32)],
    scope: Annotated[str, Form(max_length=16)],
    if_match: Annotated[str, Form()],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.MANAGE_ACCESS,
        ),
    )
    try:
        resolved_role = Role(role)
        resolved_scope = GrantScope(scope)
    except ValueError:
        return _grant_form_error_response(
            request,
            session,
            object_id,
            error="Unsupported grant role or scope.",
            status_code=422,
        )
    try:
        execute_ui_command(
            session,
            context,
            lambda: create_managed_grant(
                session,
                context,
                object_id=object_id,
                principal_id=principal_id,
                role=resolved_role,
                scope=resolved_scope,
                expected_revision=if_match,
            ),
        )
    except HTTPException as exc:
        return _grant_form_error_response(
            request,
            session,
            object_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(
        url=f"{_detail_redirect_url(request, object_id)}&edit=permissions",
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/permissions/grants/{grant_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def update_object_grant_from_ui(
    request: Request,
    object_id: str,
    grant_id: int,
    session: Annotated[Session, Depends(get_session)],
    role: Annotated[str, Form(max_length=32)],
    scope: Annotated[str, Form(max_length=16)],
    if_match: Annotated[str, Form()],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.MANAGE_ACCESS,
        ),
    )
    try:
        resolved_role = Role(role)
        resolved_scope = GrantScope(scope)
    except ValueError:
        return _grant_form_error_response(
            request,
            session,
            object_id,
            error="Unsupported grant role or scope.",
            status_code=422,
        )
    try:
        execute_ui_command(
            session,
            context,
            lambda: update_managed_grant(
                session,
                context,
                object_id=object_id,
                grant_id=grant_id,
                role=resolved_role,
                scope=resolved_scope,
                expected_revision=if_match,
            ),
        )
    except HTTPException as exc:
        return _grant_form_error_response(
            request,
            session,
            object_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(
        url=f"{_detail_redirect_url(request, object_id)}&edit=permissions",
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/permissions/grants/{grant_id}/revoke",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def revoke_object_grant_from_ui(
    request: Request,
    object_id: str,
    grant_id: int,
    session: Annotated[Session, Depends(get_session)],
    if_match: Annotated[str, Form()],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.MANAGE_ACCESS,
        ),
    )
    try:
        execute_ui_command(
            session,
            context,
            lambda: revoke_managed_grant(
                session,
                context,
                object_id=object_id,
                grant_id=grant_id,
                expected_revision=if_match,
            ),
        )
    except HTTPException as exc:
        return _grant_form_error_response(
            request,
            session,
            object_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(
        url=f"{_detail_redirect_url(request, object_id)}&edit=permissions",
        status_code=303,
    )


@router.post(
    "/objects",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def save_object(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    label: Annotated[str | None, Form()] = None,
    primary_name: Annotated[str | None, Form()] = None,
    labels: Annotated[str, Form()] = "",
    platform: Annotated[str, Form()] = "",
    hostname: Annotated[str | None, Form()] = None,
    device_category: Annotated[str | None, Form()] = None,
    device_manufacturer: Annotated[str | None, Form()] = None,
    device_model: Annotated[str | None, Form()] = None,
    status: Annotated[str, Form()] = "active",
    summary: Annotated[str, Form()] = "",
    data_json: Annotated[str, Form()] = "{}",
    hosted_on_system_id: Annotated[str, Form()] = "",
    relation_target_ref: Annotated[str, Form()] = "",
    relation_type: Annotated[str, Form()] = "hosts",
    idempotency_key: Annotated[str, Form(max_length=128)] = "",
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    if not access.policy.authorized_ids(Permission.CREATE_CHILD):
        execute_ui_command(
            session,
            context,
            lambda: _raise_command_denial(
                object_id="<placement-parent>",
                permission=Permission.CREATE_CHILD,
            ),
        )
    form = {
        "id": object_id,
        "kind": kind,
        "label": label or "",
        "primary_name": primary_name or hostname or label or "",
        "labels": labels,
        "platform": platform,
        "hostname": hostname or "",
        "device_category": device_category or "",
        "device_manufacturer": device_manufacturer or "",
        "device_model": device_model or "",
        "status": status,
        "summary": summary,
        "data_json": data_json,
        "hosted_on_system_id": hosted_on_system_id,
        "relation_target_ref": relation_target_ref,
        "relation_type": relation_type,
        "idempotency_key": idempotency_key,
    }
    try:
        data = json.loads(data_json or "{}")
        _reject_secret_shaped_form_data(data)
        ui_schema = get_ui_schema(kind)
        label_values = _split_label_values(labels)
        if label_values:
            data["labels"] = label_values
        else:
            data.pop("labels", None)
        if ui_schema.supports_platform:
            if platform and platform not in PLATFORM_TYPES:
                raise ValueError("Unsupported platform")
            if platform:
                data["platform"] = platform
            else:
                data.pop("platform", None)
        else:
            data.pop("platform", None)
        primary_value = (primary_name or hostname or label or object_id).strip()
        _apply_primary_name(data, ui_schema, primary_value)
        if kind == DEVICE_OBJECT_KIND:
            _apply_device_fields(
                data,
                category=device_category or "",
                manufacturer=device_manufacturer,
                model=device_model,
            )
        hosted_on_system_id = hosted_on_system_id.strip()
        relation_target_ref = relation_target_ref.strip()
        if hosted_on_system_id and not relation_target_ref:
            relation_target_ref = f"system:{hosted_on_system_id}"
            relation_type = "hosts"
        payload = CatalogObjectIn(
            id=object_id,
            kind=kind,
            label=primary_value or object_id,
            status=status or "active",
            summary=summary or None,
            data=data,
        )
        if not relation_target_ref:
            raise ValueError("An authorized placement parent is required")
        if ":" not in relation_target_ref:
            raise ValueError("An authorized placement parent is required")
        parent_kind, parent_id = relation_target_ref.split(":", 1)
        execute_ui_command(
            session,
            context,
            lambda: authorize_object_command(
                session,
                context,
                object_id=parent_id,
                permission=Permission.CREATE_CHILD,
            ),
        )
        parent = get_object(session, parent_id)
        if parent is None or parent.kind != parent_kind:
            raise ValueError("Parent reference does not match the authorized object")
        command_result = None
        if kind == DEVICE_OBJECT_KIND:
            if relation_type != ATTACHMENT_RELATION_TYPE:
                raise ValueError("Device creation requires an attachment parent")
            command_result = execute_ui_command(
                session,
                context,
                lambda: create_attached_device(
                    session,
                    context,
                    parent_id=parent_id,
                    payload=payload,
                    metadata={},
                    idempotency_key=idempotency_key,
                    idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
                ),
            )
        else:
            if relation_type != "hosts":
                raise ValueError("Child creation requires the hosts placement relation")
            command_result = execute_ui_command(
                session,
                context,
                lambda: create_child_object(
                    session,
                    context,
                    parent_id=parent_id,
                    payload=payload,
                    idempotency_key=idempotency_key,
                    idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
                ),
            )
    except (HTTPException, json.JSONDecodeError, ValidationError, ValueError) as exc:
        form["data_json"] = SAFE_DATA_JSON_FALLBACK
        read_model = query_catalog_browse(
            session,
            read_access_from_request(request),
        )
        return templates.TemplateResponse(
            request,
            "index.html",
            context=_index_template_context(
                request,
                read_model,
                q="",
                kind="",
                view="catalog",
                form=form,
                error=(
                    str(exc.detail)
                    if isinstance(exc, HTTPException)
                    else _safe_error_message(exc)
                ),
                show_create_form=True,
                can_write_enabled=True,
                form_kind=kind,
            ),
            status_code=exc.status_code if isinstance(exc, HTTPException) else 422,
        )
    notice = "device-created-replayed" if command_result.replayed else "device-created"
    return RedirectResponse(
        url=(
            f"{_detail_redirect_url(request, payload.id)}&notice={notice}"
            if kind == DEVICE_OBJECT_KIND
            else _detail_redirect_url(request, payload.id)
        ),
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/relationships",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def save_relationship(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    direction: Annotated[str, Form()],
    relation_type: Annotated[str, Form()],
    target_ref: Annotated[str, Form()],
    if_match: Annotated[str, Form()] = "",
    source_interface: Annotated[str, Form(max_length=128)] = "",
    target_interface_or_port: Annotated[str, Form(max_length=128)] = "",
    link_kind: Annotated[str, Form(max_length=32)] = "",
    primary: Annotated[str | None, Form()] = None,
    note: Annotated[str, Form(max_length=512)] = "",
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.WRITE,
        ),
    )
    catalog_object = get_object(session, object_id)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    try:
        if relation_type not in RELATION_TYPES:
            raise ValueError("Unsupported relation type")
        if direction not in {"inbound", "outbound"}:
            raise ValueError("Unsupported relationship direction")
        object_ref = f"{catalog_object.kind}:{catalog_object.id}"
        if direction == "inbound":
            from_ref, to_ref = target_ref, object_ref
        else:
            from_ref, to_ref = object_ref, target_ref
        metadata = _relationship_metadata_from_form(
            relation_type,
            source_interface=source_interface,
            target_interface_or_port=target_interface_or_port,
            link_kind=link_kind,
            primary=primary,
            note=note,
        )
        result = execute_ui_command(
            session,
            context,
            lambda: create_object_relationship(
                session,
                context,
                object_id=object_id,
                from_ref=from_ref,
                relation_type=relation_type,
                to_ref=to_ref,
                metadata=metadata,
                expected_revision=_ui_expected_revision(
                    request,
                    if_match,
                    catalog_object.revision,
                ),
            ),
        )
    except (
        HTTPException,
        PlacementError,
        RelationshipIntegrityError,
        ValueError,
    ) as exc:
        error = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
        return _render_object_detail(
            request,
            session,
            object_id,
            error=error,
            edit_section="relationship-add",
            can_write_enabled=True,
            relationship_form={
                "target_ref": target_ref,
                "source_interface": source_interface,
                "target_interface_or_port": target_interface_or_port,
                "link_kind": link_kind,
                "primary": primary is not None,
                "note": note,
            },
            status_code=(
                exc.status_code
                if isinstance(exc, HTTPException)
                and (
                    relation_type == ATTACHMENT_RELATION_TYPE
                    or exc.status_code in {403, 404, 412}
                )
                else 422
            ),
        )
    notice_code = "relationship-noop"
    if result.changed:
        notice_code = (
            "relationship-attached"
            if relation_type == ATTACHMENT_RELATION_TYPE
            else "relationship-saved"
        )
    return RedirectResponse(
        url=f"{_detail_redirect_url(request, object_id)}&notice={notice_code}",
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/relationships/detach",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def detach_relationship(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    from_ref: Annotated[str, Form()],
    to_ref: Annotated[str, Form()],
    if_match: Annotated[str, Form()] = "",
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.WRITE,
        ),
    )
    try:
        execute_ui_command(
            session,
            context,
            lambda: delete_object_relationship(
                session,
                context,
                object_id=object_id,
                from_ref=from_ref,
                relation_type=ATTACHMENT_RELATION_TYPE,
                to_ref=to_ref,
                expected_revision=if_match,
            ),
        )
    except HTTPException as exc:
        return _render_object_detail(
            request,
            session,
            object_id,
            error=str(exc.detail),
            edit_section="relationships",
            can_write_enabled=True,
            status_code=exc.status_code,
        )
    return RedirectResponse(
        url=f"{_detail_redirect_url(request, object_id)}&notice=relationship-detached",
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/comment",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def update_comment(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    comment: Annotated[str, Form()] = "",
    if_match: Annotated[str, Form()] = "",
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.WRITE,
        ),
    )
    existing_object = get_object(session, object_id)
    if existing_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    data = _editable_data_copy(existing_object.data)
    cleaned_comment = comment.strip()
    if cleaned_comment:
        data["comment"] = cleaned_comment
    else:
        data.pop("comment", None)
    _reject_secret_shaped_form_data(data)
    execute_ui_command(
        session,
        context,
        lambda: update_catalog_object(
            session,
            context,
            object_id=object_id,
            payload=CatalogObjectIn(
                id=existing_object.id,
                kind=existing_object.kind,
                label=existing_object.label,
                status=existing_object.status,
                summary=existing_object.summary,
                data=data,
            ),
            expected_revision=_ui_expected_revision(
                request,
                if_match,
                existing_object.revision,
            ),
        ),
    )
    return RedirectResponse(
        url=_detail_redirect_url(request, object_id),
        status_code=303,
    )


@router.post(
    "/objects/{object_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def update_object(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    label: Annotated[str | None, Form()] = None,
    primary_name: Annotated[str | None, Form()] = None,
    kind: Annotated[str | None, Form()] = None,
    status: Annotated[str | None, Form()] = None,
    platform: Annotated[str | None, Form()] = None,
    summary: Annotated[str | None, Form()] = None,
    hostname: Annotated[str | None, Form()] = None,
    container_id: Annotated[str | None, Form()] = None,
    container_label: Annotated[str | None, Form()] = None,
    hardware_model: Annotated[str | None, Form()] = None,
    hardware_cpu_vendor: Annotated[str | None, Form()] = None,
    hardware_cpu_name: Annotated[str | None, Form()] = None,
    hardware_cpu_cores: Annotated[str | None, Form()] = None,
    hardware_memory: Annotated[str | None, Form()] = None,
    hardware_gpu: Annotated[str | None, Form()] = None,
    hardware_storage: Annotated[str | None, Form()] = None,
    device_category: Annotated[str | None, Form()] = None,
    device_manufacturer: Annotated[str | None, Form()] = None,
    device_model: Annotated[str | None, Form()] = None,
    service_sources: Annotated[str | None, Form()] = None,
    service_running_version: Annotated[str | None, Form()] = None,
    data_json: Annotated[str | None, Form()] = None,
    if_match: Annotated[str, Form()] = "",
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.WRITE,
        ),
    )
    submitted_hardware = any(
        value is not None
        for value in (
            hardware_model,
            hardware_cpu_vendor,
            hardware_cpu_name,
            hardware_cpu_cores,
            hardware_memory,
            hardware_gpu,
            hardware_storage,
        )
    )
    submitted_service_information = any(
        value is not None
        for value in (
            service_sources,
            service_running_version,
        )
    )
    submitted_device = any(
        value is not None
        for value in (
            device_category,
            device_manufacturer,
            device_model,
        )
    )
    try:
        existing_object = get_object(session, object_id)
        if existing_object is None:
            raise HTTPException(status_code=404, detail="Catalog object not found")
        target_kind = kind or existing_object.kind
        data = _editable_data_copy(
            existing_object.data if data_json is None else json.loads(data_json or "{}")
        )
        ui_schema = get_ui_schema(target_kind)
        primary_value = None
        if primary_name is not None or hostname is not None or label is not None:
            primary_value = (primary_name or hostname or label or "").strip()
            _apply_primary_name(data, ui_schema, primary_value)
        if platform is not None:
            cleaned_platform = platform.strip()
            if ui_schema.supports_platform:
                if cleaned_platform and cleaned_platform not in PLATFORM_TYPES:
                    raise ValueError("Unsupported platform")
                if cleaned_platform:
                    data["platform"] = cleaned_platform
                else:
                    data.pop("platform", None)
            else:
                data.pop("platform", None)
        if container_id is not None or container_label is not None:
            container = dict(
                data.get("container") if isinstance(data.get("container"), Mapping) else {}
            )
            if container_id is not None:
                container["id"] = container_id.strip()
            if container_label is not None:
                container["label"] = container_label.strip()
            if container:
                data["container"] = container
        if target_kind in HARDWARE_OBJECT_KINDS and submitted_hardware:
            allowed_hardware_fields = {
                str(field["key"])
                for field in schema_field_payload(ui_schema)
                if str(field["key"]).startswith("hardware_")
            }
            _apply_hardware_fields(
                data,
                model=hardware_model if "hardware_model" in allowed_hardware_fields else None,
                cpu_vendor=(
                    hardware_cpu_vendor
                    if "hardware_cpu_vendor" in allowed_hardware_fields
                    else None
                ),
                cpu_name=(
                    hardware_cpu_name if "hardware_cpu_name" in allowed_hardware_fields else None
                ),
                cpu_cores=(
                    hardware_cpu_cores
                    if "hardware_cpu_cores" in allowed_hardware_fields
                    else None
                ),
                memory=hardware_memory if "hardware_memory" in allowed_hardware_fields else None,
                gpu=hardware_gpu if "hardware_gpu" in allowed_hardware_fields else None,
                storage=hardware_storage if "hardware_storage" in allowed_hardware_fields else None,
            )
        if target_kind == DEVICE_OBJECT_KIND and submitted_device:
            allowed_device_fields = {
                str(field["key"])
                for field in schema_field_payload(ui_schema)
                if str(field["key"]).startswith("device_")
            }
            _apply_device_fields(
                data,
                category=device_category if "device_category" in allowed_device_fields else None,
                manufacturer=(
                    device_manufacturer
                    if "device_manufacturer" in allowed_device_fields
                    else None
                ),
                model=device_model if "device_model" in allowed_device_fields else None,
            )
        if target_kind in SERVICE_INFORMATION_OBJECT_KINDS and submitted_service_information:
            allowed_service_information_fields = {
                str(field["key"])
                for field in schema_field_payload(ui_schema)
                if str(field["key"]).startswith("service_")
            }
            _apply_service_information_fields(
                data,
                sources=(
                    service_sources
                    if "service_sources" in allowed_service_information_fields
                    else None
                ),
                running_version=(
                    service_running_version
                    if "service_running_version" in allowed_service_information_fields
                    else None
                ),
            )
        _reject_secret_shaped_form_data(data)
        payload = CatalogObjectIn(
            id=object_id,
            kind=target_kind,
            label=primary_value or label or existing_object.label,
            status=status or existing_object.status or "active",
            summary=existing_object.summary if summary is None else summary or None,
            data=data,
        )
        execute_ui_command(
            session,
            context,
            lambda: update_catalog_object(
                session,
                context,
                object_id=object_id,
                payload=payload,
                expected_revision=_ui_expected_revision(
                    request,
                    if_match,
                    existing_object.revision,
                ),
            ),
        )
    except (HTTPException, json.JSONDecodeError, ValidationError, ValueError) as exc:
        read_model = query_catalog_detail(
            session,
            object_id,
            read_access_from_request(request),
        )
        if read_model is None:
            raise HTTPException(status_code=404, detail="Catalog object not found") from exc
        return _render_object_detail(
            request,
            session,
            object_id,
            read_model=read_model,
            error=(
                str(exc.detail)
                if isinstance(exc, HTTPException)
                else _safe_error_message(exc)
            ),
            edit_section=(
                "device"
                if submitted_device
                else "service-information"
                if submitted_service_information
                else "hardware" if submitted_hardware else "overview"
            ),
            can_write_enabled=True,
            data_json_override=SAFE_DATA_JSON_FALLBACK,
            form_rows=(
                {
                    "device_fields": [
                        {
                            "category": device_category or "",
                            "manufacturer": device_manufacturer or "",
                            "model": device_model or "",
                        }
                    ]
                }
                if submitted_device
                else None
            ),
            status_code=exc.status_code if isinstance(exc, HTTPException) else 422,
        )
    return RedirectResponse(
        url=_detail_redirect_url(request, payload.id),
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/network",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
async def update_network(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.WRITE,
        ),
    )
    existing_object = get_object(session, object_id)
    if existing_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    form = await request.form()
    if_match = str(form.get("if_match") or "")
    submitted_rows = _network_form_rows(form)
    translator = translation_context(request)["t"]
    try:
        data = _editable_data_copy(existing_object.data)
        network = dict(
            data.get("network")
            if isinstance(data.get("network"), Mapping)
            else {}
        )
        if existing_object.kind in NETWORK_ADDRESS_EDIT_KINDS:
            addresses = _validated_address_rows(
                network.get("addresses"),
                submitted_rows["network_addresses"],
                translator,
            )
            if addresses:
                network["addresses"] = addresses
            else:
                network.pop("addresses", None)
            if network:
                data["network"] = network
            else:
                data.pop("network", None)
        if existing_object.kind in NETWORK_PORT_EDIT_KINDS:
            data["ports"] = _validated_port_rows(
                data.get("ports"),
                submitted_rows["network_ports"],
                translator,
            )
        if existing_object.kind in NETWORK_ENDPOINT_EDIT_KINDS:
            data["endpoints"] = _validated_endpoint_rows(
                data.get("endpoints"),
                submitted_rows["network_endpoints"],
                translator,
            )
        _reject_secret_shaped_form_data(data)
        payload = CatalogObjectIn(
            id=existing_object.id,
            kind=existing_object.kind,
            label=existing_object.label,
            status=existing_object.status,
            summary=existing_object.summary,
            data=data,
        )
    except (ValidationError, ValueError) as exc:
        return _detail_form_error_response(
            request,
            session,
            object_id,
            error=_safe_error_message(exc),
            edit_section="network",
            form_rows=submitted_rows,
        )
    execute_ui_command(
        session,
        context,
        lambda: update_catalog_object(
            session,
            context,
            object_id=object_id,
            payload=payload,
            expected_revision=_ui_expected_revision(
                request,
                if_match,
                existing_object.revision,
            ),
        ),
    )
    return RedirectResponse(
        url=_detail_redirect_url(request, object_id),
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/access",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
async def update_access(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: authorize_object_command(
            session,
            context,
            object_id=object_id,
            permission=Permission.WRITE,
        ),
    )
    read_model = query_catalog_detail(
        session,
        object_id,
        read_access_from_request(request),
    )
    if read_model is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    form = await request.form()
    if_match = str(form.get("if_match") or "")
    submitted_rows = _access_form_rows(form, read_model)
    translator = translation_context(request)["t"]
    allowed_sources = {
        f"{read_model.catalog_object.kind}:{read_model.catalog_object.id}"
    }
    changed_objects: dict[str, CatalogObjectOut] = {}
    changed_data: dict[str, dict[str, Any]] = {}
    seen_rows: set[tuple[str, int]] = set()
    try:
        for row_number, row in enumerate(submitted_rows, start=1):
            ref = str(row["source_ref"])
            method_type = str(row["type"]).strip()
            endpoint = str(row["endpoint"]).strip()
            auth_mode = str(row["auth_mode"]).strip()
            if not method_type and not endpoint and not auth_mode:
                continue
            if ref not in allowed_sources or ":" not in ref:
                raise ValueError(
                    translator("validation.access_source_invalid", row=row_number)
                )
            if not method_type:
                raise ValueError(
                    translator("validation.access_type_required", row=row_number)
                )
            if not endpoint:
                raise ValueError(
                    translator("validation.access_endpoint_required", row=row_number)
                )
            try:
                index = int(str(row["index"]))
            except ValueError as exc:
                raise ValueError(
                    translator("validation.access_row_invalid", row=row_number)
                ) from exc
            if index < 0 or (ref, index) in seen_rows:
                raise ValueError(
                    translator("validation.access_row_invalid", row=row_number)
                )
            seen_rows.add((ref, index))
            kind, target_id = ref.split(":", 1)
            target = changed_objects.get(ref) or get_object(session, target_id)
            if target is None or target.kind != kind:
                raise ValueError(
                    translator("validation.access_source_invalid", row=row_number)
                )
            changed_objects[ref] = target
            data = changed_data.setdefault(ref, _editable_data_copy(target.data))
            methods = data.get("access_methods")
            if not isinstance(methods, list):
                methods = []
                data["access_methods"] = methods
            if index > len(methods):
                raise ValueError(
                    translator("validation.access_row_invalid", row=row_number)
                )
            if index == len(methods):
                methods.append({})
            if not isinstance(methods[index], dict):
                methods[index] = {}
            method_payload = {
                **methods[index],
                "type": method_type,
                "endpoint": endpoint,
            }
            if auth_mode:
                method_payload["auth_mode"] = auth_mode
            else:
                method_payload.pop("auth_mode", None)
            methods[index] = method_payload
        payloads: list[CatalogObjectIn] = []
        for ref, data in changed_data.items():
            _reject_secret_shaped_form_data(data)
            target = changed_objects[ref]
            payloads.append(
                CatalogObjectIn(
                    id=target.id,
                    kind=target.kind,
                    label=target.label,
                    status=target.status,
                    summary=target.summary,
                    data=data,
                )
            )
    except (ValidationError, ValueError) as exc:
        return _detail_form_error_response(
            request,
            session,
            object_id,
            error=_safe_error_message(exc),
            edit_section="access",
            form_rows={"access_methods": submitted_rows},
        )
    if len(payloads) > 1:
        raise HTTPException(
            status_code=409,
            detail="One object may be changed per command",
        )
    if payloads:
        execute_ui_command(
            session,
            context,
            lambda: update_catalog_object(
                session,
                context,
                object_id=object_id,
                payload=payloads[0],
                expected_revision=_ui_expected_revision(
                    request,
                    if_match,
                    read_model.catalog_object.revision,
                ),
            ),
        )
    return RedirectResponse(
        url=_detail_redirect_url(request, object_id),
        status_code=303,
    )


@router.post(
    "/objects/{object_id}/delete",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def delete_object_from_ui(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    if_match: Annotated[str, Form()],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    execute_ui_command(
        session,
        context,
        lambda: delete_catalog_object(
            session,
            context,
            object_id=object_id,
            expected_revision=if_match,
        ),
    )
    return RedirectResponse(url="/", status_code=303)


def _detail_form_error_response(
    request: Request,
    session: Session,
    object_id: str,
    *,
    error: str,
    edit_section: str,
    form_rows: Mapping[str, list[Mapping[str, Any]]],
):
    read_model = query_catalog_detail(
        session,
        object_id,
        read_access_from_request(request),
    )
    if read_model is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return _render_object_detail(
        request,
        session,
        object_id,
        read_model=read_model,
        error=error,
        edit_section=edit_section,
        can_write_enabled=True,
        form_rows=form_rows,
        status_code=422,
    )


def _grant_form_error_response(
    request: Request,
    session: Session,
    object_id: str,
    *,
    error: str,
    status_code: int,
) -> HTMLResponse:
    return _render_object_detail(
        request,
        session,
        object_id,
        error=error,
        edit_section="permissions",
        can_write_enabled=False,
        status_code=status_code,
    )


def _network_form_rows(form: Any) -> dict[str, list[dict[str, Any]]]:
    return {
        "network_addresses": _submitted_form_rows(
            form,
            {
                "ip": "address_ip",
                "interface": "address_interface",
                "scope": "address_scope",
            },
        ),
        "network_ports": _submitted_form_rows(
            form,
            {
                "port": "port_value",
                "protocol": "port_protocol",
                "purpose": "port_purpose",
                "exposure": "port_exposure",
            },
        ),
        "network_endpoints": _submitted_form_rows(
            form,
            {
                "type": "endpoint_type",
                "url": "endpoint_url",
                "port": "endpoint_port",
            },
        ),
    }


def _access_form_rows(form: Any, read_model: Any) -> list[dict[str, Any]]:
    rows = _submitted_form_rows(
        form,
        {
            "source_ref": "method_ref",
            "index": "method_index",
            "type": "method_type",
            "endpoint": "method_endpoint",
            "auth_mode": "method_auth_mode",
        },
    )
    catalog_object = read_model.catalog_object
    source_details = {
        str(method["source_ref"]): (
            str(method["source_kind"]),
            str(method["source_label"]),
        )
        for method in _display_access_methods(
            catalog_object,
            read_model.relationship_groups,
            read_model.object_map,
        )
    }
    source_details[f"{catalog_object.kind}:{catalog_object.id}"] = (
        catalog_object.kind,
        catalog_object.label,
    )
    for row in rows:
        source_kind, source_label = source_details.get(
            str(row["source_ref"]),
            ("?", str(row["source_ref"])),
        )
        row["source_kind"] = source_kind
        row["source_label"] = source_label
    return rows


def _submitted_form_rows(
    form: Any,
    field_names: Mapping[str, str],
) -> list[dict[str, Any]]:
    values = {
        output_name: [str(value) for value in form.getlist(input_name)]
        for output_name, input_name in field_names.items()
    }
    count = max((len(items) for items in values.values()), default=0)
    return [
        {
            output_name: items[index] if index < len(items) else ""
            for output_name, items in values.items()
        }
        for index in range(count)
    ]


def _validated_address_rows(
    existing: Any,
    rows: list[Mapping[str, Any]],
    translator: Any,
) -> list[dict[str, Any]]:
    originals = _padded_mappings(existing, len(rows))
    validated: list[dict[str, Any]] = []
    for row_number, (original, row) in enumerate(
        zip(originals, rows, strict=True),
        start=1,
    ):
        ip_value = str(row.get("ip") or "").strip()
        interface = str(row.get("interface") or "").strip()
        scope = str(row.get("scope") or "").strip()
        if not ip_value and not interface and not scope:
            continue
        if not ip_value:
            raise ValueError(
                translator("validation.network_ip_required", row=row_number)
            )
        try:
            ip_address(ip_value)
        except ValueError as exc:
            raise ValueError(
                translator("validation.network_ip_invalid", row=row_number)
            ) from exc
        payload = dict(original)
        payload["ip"] = ip_value
        payload.pop("network", None)
        for key, value in {"interface": interface, "scope": scope}.items():
            if value:
                payload[key] = value
            else:
                payload.pop(key, None)
        validated.append(payload)
    return validated


def _validated_port_rows(
    existing: Any,
    rows: list[Mapping[str, Any]],
    translator: Any,
) -> list[dict[str, Any]]:
    originals = _padded_mappings(existing, len(rows))
    validated: list[dict[str, Any]] = []
    for row_number, (original, row) in enumerate(
        zip(originals, rows, strict=True),
        start=1,
    ):
        port_text = str(row.get("port") or "").strip()
        protocol = str(row.get("protocol") or "").strip()
        purpose = str(row.get("purpose") or "").strip()
        exposure = str(row.get("exposure") or "").strip()
        if (
            not port_text
            and protocol in {"", "tcp"}
            and not purpose
            and not exposure
        ):
            continue
        port = _validated_port(port_text, translator, row_number)
        payload = {
            **original,
            "port": port,
            "protocol": protocol or "tcp",
        }
        for key, value in {"purpose": purpose, "exposure": exposure}.items():
            if value:
                payload[key] = value
            else:
                payload.pop(key, None)
        validated.append(payload)
    return validated


def _validated_endpoint_rows(
    existing: Any,
    rows: list[Mapping[str, Any]],
    translator: Any,
) -> list[dict[str, Any]]:
    originals = _padded_mappings(existing, len(rows))
    validated: list[dict[str, Any]] = []
    for row_number, (original, row) in enumerate(
        zip(originals, rows, strict=True),
        start=1,
    ):
        endpoint_type = str(row.get("type") or "").strip()
        url = str(row.get("url") or "").strip()
        port_text = str(row.get("port") or "").strip()
        if not endpoint_type and not url and not port_text:
            continue
        if not endpoint_type:
            raise ValueError(
                translator("validation.endpoint_type_required", row=row_number)
            )
        if not _normalize_endpoint_type(endpoint_type):
            raise ValueError(
                translator(
                    "validation.endpoint_type_invalid",
                    row=row_number,
                    allowed=", ".join(ENDPOINT_TYPES),
                )
            )
        if not url:
            raise ValueError(
                translator("validation.endpoint_url_required", row=row_number)
            )
        port = (
            _validated_port(
                port_text,
                translator,
                row_number,
                message_key="validation.endpoint_port_invalid",
            )
            if port_text
            else ""
        )
        validated.append(
            _endpoint_payload(original, endpoint_type, url, port)
        )
    return validated


def _validated_port(
    value: str,
    translator: Any,
    row_number: int,
    *,
    message_key: str = "validation.port_invalid",
) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(translator(message_key, row=row_number)) from exc
    if not 1 <= port <= 65535:
        raise ValueError(translator(message_key, row=row_number))
    return port


def _empty_form() -> dict[str, str]:
    return {
        "id": "",
        "kind": "system",
        "label": "",
        "primary_name": "",
        "labels": "",
        "platform": "",
        "hostname": "",
        "device_category": "",
        "device_manufacturer": "",
        "device_model": "",
        "status": "active",
        "summary": "",
        "data_json": SAFE_DATA_JSON_FALLBACK,
        "hosted_on_system_id": "",
        "relation_target_ref": "",
        "relation_type": "hosts",
        "idempotency_key": uuid4().hex,
    }


def _ui_expected_revision(
    _request: Request,
    if_match: str,
    _current_revision: int,
) -> int | str | None:
    if if_match:
        return if_match
    return None


def _raise_command_denial(
    *,
    object_id: str,
    permission: Permission,
) -> None:
    raise CommandAuthorizationDenied(
        object_id=object_id,
        permission=permission,
    )


def _split_label_values(raw_labels: str) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for value in re.split(r"[,;\n]+", raw_labels):
        label = value.strip()
        if not label or label.casefold() in seen:
            continue
        seen.add(label.casefold())
        labels.append(label)
    return labels


def _require_existing_ref(session: Session, ref: str) -> None:
    if ":" not in ref:
        raise HTTPException(status_code=422, detail="Invalid object reference")
    kind, object_id = ref.split(":", 1)
    target = get_object(session, object_id)
    if target is None or target.kind != kind:
        raise HTTPException(status_code=422, detail="Relationship target does not exist")


def _reject_secret_shaped_form_data(data: object) -> None:
    violations = find_secret_violations(data)
    if violations:
        raise ValueError("; ".join(violations))


def _safe_error_message(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"data_json is not valid JSON: {exc.msg}"
    if isinstance(exc, ValidationError):
        return "Invalid catalog object payload."
    if isinstance(exc, ValueError):
        return str(exc)
    return "Invalid catalog object payload."


def _apply_primary_name(data: dict[str, Any], schema: Any, value: str) -> None:
    if schema.primary_name_storage != "network_hostname":
        return
    network = dict(data.get("network") if isinstance(data.get("network"), Mapping) else {})
    existing_hostnames = network.get("hostnames")
    hostname_values = (
        [str(hostname) for hostname in existing_hostnames]
        if isinstance(existing_hostnames, list)
        else []
    )
    network["hostnames"] = [value, *hostname_values[1:]] if value else hostname_values[1:]
    if network["hostnames"] or network.get("addresses") or network.get("mac_addresses"):
        data["network"] = network
    else:
        data.pop("network", None)


def _access_method_rows(
    catalog_object: CatalogObjectOut,
    access_methods: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if access_methods:
        return access_methods
    return [
        {
            "type": "",
            "endpoint": "",
            "auth_mode": "",
            "source_kind": catalog_object.kind,
            "source_label": catalog_object.label,
            "source_ref": f"{catalog_object.kind}:{catalog_object.id}",
            "index": 0,
        }
    ]


def _display_access_methods(
    catalog_object: CatalogObjectOut,
    relationship_groups: dict[str, list[RelatedRelationshipReadModel]],
    object_map: dict[str, CatalogObjectOut],
) -> list[dict[str, Any]]:
    methods = _access_methods(
        catalog_object.data,
        source_kind=catalog_object.kind,
        source_label=catalog_object.label,
        source_ref=f"{catalog_object.kind}:{catalog_object.id}",
    )
    if catalog_object.kind != "system":
        return methods
    for relationship in relationship_groups.get("outbound", []):
        if relationship.get("relation_type") != "hosts":
            continue
        service = object_map.get(relationship.get("to_ref", ""))
        if service is None or service.kind != "service":
            continue
        methods.extend(
            _access_methods(
                service.data,
                source_kind="service",
                source_label=service.label,
                source_ref=f"service:{service.id}",
            )
        )
    return methods


def _network_summary(data: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]] | list[str]]:
    network = data.get("network")
    if not isinstance(network, Mapping):
        return {"hostnames": [], "addresses": [], "mac_addresses": []}
    hostnames = network.get("hostnames")
    hostname_values = (
        [str(hostname) for hostname in hostnames]
        if isinstance(hostnames, list)
        else []
    )
    return {
        "hostnames": hostname_values,
        "addresses": _list_of_mappings(network.get("addresses")),
        "mac_addresses": _list_of_mappings(network.get("mac_addresses")),
    }


def _container_summary(data: Mapping[str, Any]) -> Mapping[str, Any] | None:
    container = data.get("container")
    return container if isinstance(container, Mapping) else None


def _hardware_summary(data: Mapping[str, Any]) -> dict[str, str]:
    hardware = data.get("hardware")
    if not isinstance(hardware, Mapping):
        return {
            "model": "",
            "cpu_vendor": "",
            "cpu_name": "",
            "cpu_cores": "",
            "memory": "",
            "gpu": "",
            "storage": "",
        }
    cpu = hardware.get("cpu")
    cpu_data = cpu if isinstance(cpu, Mapping) else {}
    return {
        "model": str(hardware.get("model") or ""),
        "cpu_vendor": str(cpu_data.get("vendor") or ""),
        "cpu_name": str(cpu_data.get("name") or ""),
        "cpu_cores": str(cpu_data.get("cores") or ""),
        "memory": str(hardware.get("memory") or ""),
        "gpu": str(hardware.get("gpu") or ""),
        "storage": str(hardware.get("storage") or ""),
    }


def _hardware_schema_fields(
    schema_fields: list[dict[str, object]],
    hardware: Mapping[str, str],
) -> list[dict[str, str]]:
    hardware_values = {
        "hardware_model": hardware.get("model", ""),
        "hardware_cpu_vendor": hardware.get("cpu_vendor", ""),
        "hardware_cpu_name": hardware.get("cpu_name", ""),
        "hardware_cpu_cores": hardware.get("cpu_cores", ""),
        "hardware_memory": hardware.get("memory", ""),
        "hardware_gpu": hardware.get("gpu", ""),
        "hardware_storage": hardware.get("storage", ""),
    }
    return [
        {
            "key": str(field["key"]),
            "label": str(field["label"]),
            "placeholder": str(field["placeholder"] or ""),
            "value": hardware_values.get(str(field["key"]), ""),
        }
        for field in schema_fields
        if str(field["key"]).startswith("hardware_")
    ]


def _service_information_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    service_information = data.get("service_information")
    if not isinstance(service_information, Mapping):
        return {
            "sources": [],
            "sources_text": "",
            "running_version": "",
        }
    raw_sources = service_information.get("sources")
    if isinstance(raw_sources, list):
        sources = [str(source) for source in raw_sources if str(source).strip()]
    elif isinstance(raw_sources, str):
        sources = _split_multivalue(raw_sources)
    else:
        sources = []
    return {
        "sources": sources,
        "sources_text": "\n".join(sources),
        "running_version": str(service_information.get("running_version") or ""),
    }


def _service_information_schema_fields(
    schema_fields: list[dict[str, object]],
    service_information: Mapping[str, Any],
) -> list[dict[str, str]]:
    service_information_values = {
        "service_sources": str(service_information.get("sources_text") or ""),
        "service_running_version": str(service_information.get("running_version") or ""),
    }
    return [
        {
            "key": str(field["key"]),
            "label": str(field["label"]),
            "placeholder": str(field["placeholder"] or ""),
            "value": service_information_values.get(str(field["key"]), ""),
        }
        for field in schema_fields
        if str(field["key"]).startswith("service_")
    ]


def _apply_hardware_fields(
    data: dict[str, Any],
    *,
    model: str | None,
    cpu_vendor: str | None,
    cpu_name: str | None,
    cpu_cores: str | None,
    memory: str | None,
    gpu: str | None,
    storage: str | None,
) -> None:
    existing_hardware = data.get("hardware")
    hardware = dict(existing_hardware if isinstance(existing_hardware, Mapping) else {})
    for key, value in {
        "model": model,
        "memory": memory,
        "gpu": gpu,
        "storage": storage,
    }.items():
        if value is None:
            continue
        clean_value = value.strip()
        if clean_value:
            hardware[key] = clean_value
        else:
            hardware.pop(key, None)
    cpu = dict(hardware.get("cpu") if isinstance(hardware.get("cpu"), Mapping) else {})
    for key, value in {
        "vendor": cpu_vendor,
        "name": cpu_name,
        "cores": cpu_cores,
    }.items():
        if value is None:
            continue
        clean_value = value.strip()
        if clean_value:
            cpu[key] = clean_value
        else:
            cpu.pop(key, None)
    if cpu:
        hardware["cpu"] = cpu
    else:
        hardware.pop("cpu", None)
    if hardware:
        data["hardware"] = hardware
    else:
        data.pop("hardware", None)


def _apply_service_information_fields(
    data: dict[str, Any],
    *,
    sources: str | None,
    running_version: str | None,
) -> None:
    service_information = dict(
        data.get("service_information")
        if isinstance(data.get("service_information"), Mapping)
        else {}
    )
    if sources is not None:
        source_values = _split_multivalue(sources)
        if source_values:
            service_information["sources"] = source_values
        else:
            service_information.pop("sources", None)
    if running_version is not None:
        service_information["running_version"] = running_version.strip()
    service_information = {key: value for key, value in service_information.items() if value}
    if service_information:
        data["service_information"] = service_information
    else:
        data.pop("service_information", None)


def _device_summary(data: Mapping[str, Any]) -> dict[str, str]:
    device = data.get("device")
    if not isinstance(device, Mapping):
        return {
            "category": "",
            "manufacturer": "",
            "model": "",
        }
    return {
        "category": str(device.get("category") or ""),
        "manufacturer": str(device.get("manufacturer") or ""),
        "model": str(device.get("model") or ""),
    }


def _supports_device_attachment_parent(catalog_object: Any) -> bool:
    if catalog_object.kind in {"host", "system", DEVICE_OBJECT_KIND}:
        return True
    if catalog_object.kind != "network":
        return False
    data = getattr(catalog_object, "data", None)
    if not isinstance(data, Mapping):
        return False
    network = data.get("network")
    return (
        isinstance(network, Mapping)
        and network.get("category") in NETWORK_DEVICE_CATEGORIES
    )


def _device_schema_fields(
    schema_fields: list[dict[str, object]],
    device: Mapping[str, str],
) -> list[dict[str, str]]:
    device_values = {
        "device_category": device.get("category", ""),
        "device_manufacturer": device.get("manufacturer", ""),
        "device_model": device.get("model", ""),
    }
    return [
        {
            "key": str(field["key"]),
            "label": str(field["label"]),
            "placeholder": str(field["placeholder"] or ""),
            "value": device_values.get(str(field["key"]), ""),
        }
        for field in schema_fields
        if str(field["key"]).startswith("device_")
    ]


def _apply_device_fields(
    data: dict[str, Any],
    *,
    category: str | None,
    manufacturer: str | None,
    model: str | None,
) -> None:
    device = dict(
        data.get("device")
        if isinstance(data.get("device"), Mapping)
        else {}
    )
    for key, value in {
        "category": category,
        "manufacturer": manufacturer,
        "model": model,
    }.items():
        if value is None:
            continue
        clean_value = value.strip()
        if clean_value:
            device[key] = clean_value
        else:
            device.pop(key, None)
    if device:
        data["device"] = device
    else:
        data.pop("device", None)


def _relationship_metadata_from_form(
    relation_type: str,
    *,
    source_interface: str,
    target_interface_or_port: str,
    link_kind: str,
    primary: str | None,
    note: str,
) -> dict[str, object]:
    if relation_type != ATTACHMENT_RELATION_TYPE:
        return {}
    if primary is not None and primary not in {"1", "on", "true"}:
        raise ValueError("Invalid primary attachment value")
    metadata: dict[str, object] = {}
    for key, value in {
        "source_interface": source_interface,
        "target_interface_or_port": target_interface_or_port,
        "link_kind": link_kind,
        "note": note,
    }.items():
        if cleaned := value.strip():
            metadata[key] = cleaned
    if primary is not None:
        metadata["primary"] = True
    return metadata


def _device_chain_rows(
    graph: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    if not graph:
        return []
    node_by_ref = {
        str(node.get("ref")): node
        for node in graph.get("nodes", [])
        if isinstance(node, Mapping) and node.get("ref")
    }
    edges = [
        edge
        for edge in graph.get("edges", [])
        if isinstance(edge, Mapping)
        and edge.get("relation_type") == ATTACHMENT_RELATION_TYPE
        and edge.get("from_ref") in node_by_ref
        and edge.get("to_ref") in node_by_ref
    ]
    children_by_parent: dict[str, list[Mapping[str, Any]]] = {}
    child_refs: set[str] = set()
    for edge in edges:
        child_ref = str(edge["from_ref"])
        parent_ref = str(edge["to_ref"])
        child_refs.add(child_ref)
        children_by_parent.setdefault(parent_ref, []).append(edge)

    def node_key(ref: str) -> tuple[str, str]:
        node = node_by_ref[ref]
        return (str(node.get("label") or ref).casefold(), ref)

    def edge_key(edge: Mapping[str, Any]) -> tuple[bool, str, str]:
        metadata = edge.get("metadata")
        return (
            not (isinstance(metadata, Mapping) and metadata.get("primary") is True),
            *node_key(str(edge["from_ref"])),
        )

    rows: list[dict[str, Any]] = []
    visited: set[str] = set()

    def add_branch(
        ref: str,
        depth: int,
        edge: Mapping[str, Any] | None = None,
    ) -> None:
        if ref in visited:
            return
        visited.add(ref)
        rows.append(
            {
                "node": node_by_ref[ref],
                "depth": depth,
                "parent_ref": str(edge["to_ref"]) if edge else "",
                "metadata": dict(edge.get("metadata") or {}) if edge else {},
                "current": ref == graph.get("object_ref"),
            }
        )
        for child_edge in sorted(children_by_parent.get(ref, []), key=edge_key):
            add_branch(str(child_edge["from_ref"]), depth + 1, child_edge)

    roots = sorted(set(node_by_ref) - child_refs, key=node_key)
    for root_ref in roots:
        add_branch(root_ref, 0)
    for remaining_ref in sorted(set(node_by_ref) - visited, key=node_key):
        add_branch(remaining_ref, 0)
    return rows


def _relationship_notice(request: Request) -> str | None:
    notice = request.query_params.get("notice", "")
    key = {
        "device-created": "device.notice.created",
        "device-created-replayed": "device.notice.created_replayed",
        "relationship-attached": "device.notice.attached",
        "relationship-detached": "device.notice.detached",
        "relationship-noop": "device.notice.noop",
        "relationship-saved": "relationship.notice.saved",
    }.get(notice)
    if key is None:
        return None
    return translation_context(request)["t"](key)


def _access_methods(
    data: Mapping[str, Any],
    *,
    source_kind: str,
    source_label: str,
    source_ref: str,
) -> list[dict[str, Any]]:
    methods = _list_of_mappings(data.get("access_methods"))
    return [
        {
            "type": str(method.get("type") or "access"),
            "endpoint": str(method.get("endpoint") or ""),
            "auth_mode": str(method.get("auth_mode") or "unknown"),
            "source_kind": source_kind,
            "source_label": source_label,
            "source_ref": source_ref,
            "index": index,
        }
        for index, method in enumerate(methods)
    ]


def _editable_data_copy(data: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(data))


def _endpoint_edit_rows(endpoints: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = _padded_mappings(endpoints, max(1, len(endpoints)))
    for row in rows:
        row["type"] = _normalize_endpoint_type(
            row.get("type") or row.get("name") or row.get("label")
        )
    return rows


def _endpoint_payload(
    endpoint: Mapping[str, Any],
    endpoint_type: object,
    url: object,
    port_value: object,
) -> dict[str, Any]:
    payload = dict(endpoint)
    payload.pop("name", None)
    payload.pop("label", None)
    normalized_type = _normalize_endpoint_type(endpoint_type)
    if not normalized_type:
        allowed = ", ".join(ENDPOINT_TYPES)
        raise ValueError(f"endpoint type must be one of: {allowed}")
    payload["type"] = normalized_type
    payload["url"] = str(url).strip()
    if str(port_value).strip():
        payload["port"] = int(port_value)
    else:
        payload.pop("port", None)
    return payload


def _normalize_endpoint_type(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    compact = re.sub(r"[^a-z0-9]+", "", raw.lower())
    aliases = {
        "web": "Web",
        "webui": "Web",
        "ui": "Web",
        "rest": "REST API",
        "restapi": "REST API",
        "api": "REST API",
        "apibase": "REST API",
        "managementapi": "REST API",
        "lanmanagementapi": "REST API",
        "publicmanagementapi": "REST API",
        "mcp": "MCP",
        "hec": "HEC",
        "ssh": "SSH",
    }
    return aliases.get(compact, raw if raw in ENDPOINT_TYPES else "")


def _split_multivalue(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def _padded_mappings(value: Any, count: int) -> list[dict[str, Any]]:
    items = [dict(item) for item in _list_of_mappings(value)]
    while len(items) < count:
        items.append({})
    return items[:count]


def _mapping_rows_override(
    override: list[Mapping[str, Any]] | None,
    fallback: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not override:
        return fallback
    return [dict(row) for row in override]


def _fields_by_key(fields: list[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {str(field["key"]): field for field in fields}


def _without_credential_references(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            if key == "credential_references":
                continue
            cleaned[key] = _without_credential_references(child)
        return cleaned
    if isinstance(value, list):
        return [
            cleaned_child
            for item in value
            if not _is_credential_ref(item)
            for cleaned_child in [_without_credential_references(item)]
        ]
    if _is_credential_ref(value):
        return ""
    return value


def _credential_references(data: Mapping[str, Any]) -> list[dict[str, str]]:
    return [
        {"ref": ref, "id": object_id_from_ref(ref)}
        for ref in sorted(_collect_credential_references(data))
    ]


def _collect_credential_references(value: Any) -> set[str]:
    references: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            if _is_credential_ref(child):
                references.add(child)
            references.update(_collect_credential_references(child))
    elif isinstance(value, list):
        for child in value:
            if _is_credential_ref(child):
                references.add(child)
            references.update(_collect_credential_references(child))
    return references


def _is_credential_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("credential_reference:")


def _list_of_mappings(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]
