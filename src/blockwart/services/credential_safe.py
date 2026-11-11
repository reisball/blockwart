"""Internal OpenBao broker. Secret payloads never enter catalog persistence."""
from __future__ import annotations

import hashlib
import json
import logging
from http.client import HTTPException as HTTPProtocolError
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.config import Settings
from blockwart.db.session import DatabaseTransactionError, transaction
from blockwart.domain.auth import Permission
from blockwart.models import CatalogObject, SafeOperation
from blockwart.services.audit import add_audit_event
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandNotFound,
    WriteContext,
    authorize_object_command,
    refresh_write_context,
)

MAX_VERSIONS = 2147483647
PRESETS = {
    "login": {"username": "", "password": ""},
    "token": {"token": ""},
    "key": {"key": "", "passphrase": ""},
    "other": {"value": ""},
}


class SafeAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["read", "history", "write", "restore", "delete", "undelete", "reconcile"]
    operation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    version: int | None = Field(default=None, ge=1, le=MAX_VERSIONS)
    cas: int | None = Field(default=None, ge=0, lt=MAX_VERSIONS)
    fields: dict[str, str] | None = None
    preset: Literal["login", "token", "key", "other"] = "other"

    @model_validator(mode="after")
    def bounded_fields(self):
        if self.action == "reconcile" and (
            self.operation_id is None or self.cas is not None or self.version is not None
            or self.fields is not None or self.preset != "other"
        ):
            raise ValueError("Reconciliation requires only an operation identity")
        if self.action in {"read", "history"} and self.operation_id is not None:
            raise ValueError("Operation identity is only accepted for mutations/reconciliation")
        if self.fields is not None and (
            len(self.fields) > 64
            or any(not k or len(k) > 128 or len(v) > 65536 for k, v in self.fields.items())
            or len(json.dumps(self.fields).encode()) > 262144
        ):
            raise ValueError("Safe fields exceed limits")
        return self


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Bao:
    def __init__(self, settings: Settings):
        self.url = settings.safe_url.rstrip("/")
        self.auth_file = settings.safe_auth_file
        if not self.url or not self.auth_file:
            raise HTTPException(503, "Credential safe unavailable")

    def call(self, method, path, body=None, *, token=None):
        try:
            request = Request(
                self.url + "/v1/" + path,
                data=json.dumps(body).encode() if body is not None else None,
                headers={"Content-Type": "application/json",
                         "X-Blockwart-Operation": getattr(self, "operation_id", ""), **(
                    {"X-Vault-Token": token} if token else {}
                )},
                method=method,
            )
            with build_opener(ProxyHandler({}), NoRedirect).open(request, timeout=5) as response:
                raw = response.read(1048577)
                expected_length = response.headers.get("Content-Length")
                if expected_length is not None and len(raw) != int(expected_length):
                    raise ValueError("incomplete response")
                if len(raw) > 1048576:
                    raise ValueError("response bound")
                result = json.loads(raw) if raw else {}
                if not isinstance(result, dict):
                    raise ValueError("response shape")
                return result
        except HTTPError as exc:
            exc.close()
            # Never publish OpenBao error text, request documents or tokens.
            if exc.code == 404:
                raise HTTPException(404, "Safe version not found") from None
            if exc.code == 400:
                raise HTTPException(409, "Safe version conflict or invalid operation") from None
            raise HTTPException(503, "Credential safe unavailable") from None
        except (HTTPProtocolError, OSError, URLError, ValueError, TypeError):
            raise HTTPException(503, "Credential safe unavailable") from None

    def token(self):
        try:
            auth = json.loads(Path(self.auth_file).read_text())
            result = self.call("POST", "auth/approle/login", {
                "role_id": auth["role_id"], "secret_id": auth["secret_id"],
            })
            token = result["auth"]["client_token"]
            if not isinstance(token, str) or not token:
                raise ValueError("invalid token")
            return token
        except (HTTPException, OSError, ValueError, KeyError, TypeError):
            raise HTTPException(503, "Credential safe unavailable") from None

    def request(self, method, path, body=None):
        token = self.token()
        try:
            if method == "POST" and path.startswith("blockwart/data/"):
                before_send = getattr(self, "before_mutation", None)
                if before_send is not None:
                    before_send()
            return self.call(method, path, body, token=token)
        finally:
            # Short-lived tokens also expire if revocation is unavailable.
            try:
                self.call("POST", "auth/token/revoke-self", {}, token=token)
            except HTTPException:
                logging.getLogger(__name__).warning(
                    "safe_token_revoke_failed operation_id=%s",
                    getattr(self, "operation_id", "unassigned"))


def _audit(session, context, object_id, command, operation_id, state):
    add_audit_event(session, object_id=object_id, action="credential_safe_" + command.action,
                    actor=context.principal.id, details={"channel": context.channel,
                    "operation_id": operation_id, "state": state})


def _finish(session, operation_id, state, version=None):
    # Record backend completion BEFORE any post-I/O authorization: revocation
    # must prevent revelation, not erase the fact that a write succeeded.
    with transaction(session):
        row = session.get(SafeOperation, operation_id)
        # Another reconciler may finish while this request reads the backend.
        # A committed successful receipt is immutable and audited only once.
        changed = session.execute(update(SafeOperation).where(
            SafeOperation.id == operation_id, SafeOperation.state != "succeeded",
        ).values(state=state, result_version=version)).rowcount
        if changed != 1:
            return
        add_audit_event(session, object_id=row.object_id,
                        action="credential_safe_" + row.action, actor=row.actor,
                        details={"channel": row.channel, "operation_id": row.id, "state": state})


def _reconcile(backend, locator, row):
    # One exact-version read, never a scan or another write. A missing version
    # does not prove nonexecution: an original request may still be in flight.
    try:
        data = backend.request("GET", "blockwart/data/" + locator +
                               "?version=" + str(row.cas + 1))["data"]
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(
                409, "Safe operation outcome pending; retry reconciliation") from None
        raise
    if _version(data["metadata"]["version"]) != row.cas + 1:
        raise ValueError("unexpected reconciliation version")
    if data["data"].get("operation_id") == row.id:
        return "succeeded", row.cas + 1, data["data"]
    return "conflict", None, None


def operate(session: Session, context: WriteContext, settings: Settings,
            object_id: str, command: SafeAction) -> dict:
    if session.new or session.dirty or session.deleted:
        raise RuntimeError("safe operation requires a clean session")
    session.rollback()
    operation_id = hashlib.sha256(json.dumps([
        "request", context.principal.id, context.channel, object_id,
        command.operation_id or uuid4().hex + uuid4().hex,
    ]).encode()).hexdigest()
    try:
        with transaction(session):
            context, identity = _authorize(session, context, object_id, command)
    except (CommandAuthorizationDenied, CommandNotFound, HTTPException):
        # Only fixed metadata, never exception text or command fields.
        with transaction(session):
            _audit(session, context, None, command, operation_id, "denied")
        raise
    locator = hashlib.sha256(identity[0].encode()).hexdigest()
    mutation = command.action not in {"read", "history"}
    if mutation:
        if command.action != "reconcile":
            _validate_mutation(command)
        operation_id = _operation_identity(identity[0], context, command)
        try:
            with transaction(session):
                row = session.get(SafeOperation, operation_id)
                if row is None:
                    if command.action == "reconcile":
                        raise HTTPException(404, "Safe operation not found")
                    row = SafeOperation(id=operation_id, actor=context.principal.id,
                        channel=context.channel, object_id=object_id, instance_id=identity[0],
                        action=command.action, cas=command.cas, source_version=command.version,
                        state="intent")
                    session.add(row)
                    _audit(session, context, object_id, command, operation_id, "intent")
                else:
                    if (row.actor, row.channel, row.object_id, row.instance_id) != (
                            context.principal.id, context.channel, object_id, identity[0]):
                        raise HTTPException(404, "Safe operation not found")
                    if command.action != "reconcile" and (
                            row.action, row.cas, row.source_version) != (
                                command.action, command.cas, command.version):
                        raise HTTPException(409, "Safe operation identity already bound")
                    # Only definitive backend rejection is reusable by legacy
                    # clients. Dispatched/unknown custody is never reset.
                    if (command.operation_id is None and command.action != "reconcile"
                            and row.state in {"conflict", "failed"}):
                        session.execute(update(SafeOperation).where(
                            SafeOperation.id == operation_id,
                            SafeOperation.state.in_(["conflict", "failed"]),
                        ).values(state="intent", result_version=None))
                        _audit(session, context, object_id, command, operation_id, "intent")
        except DatabaseTransactionError as exc:
            if isinstance(exc.__cause__, IntegrityError):
                # A competing first admission is not a database outage.
                with transaction(session):
                    admitted = session.get(SafeOperation, operation_id) is not None
                    if admitted:
                        _audit(session, context, object_id, command, operation_id, "claim_lost")
                if admitted:
                    raise HTTPException(
                        409, "Safe operation pending; retry reconciliation") from None
            raise
    else:
        with transaction(session):
            _audit(session, context, object_id, command, operation_id, "intent")

    reconciled = False
    request_outcome = None

    def after_io(*, success=False):
        nonlocal context
        try:
            with transaction(session):
                context, current = _authorize(session, context, object_id, command)
                if current != identity:
                    raise HTTPException(409, "Credential reference changed during safe operation")
                if success and (not mutation or reconciled):
                    _audit(session, context, object_id, command, operation_id,
                           "reconciled" if mutation else "succeeded")
        except (CommandAuthorizationDenied, CommandNotFound, HTTPException):
            with transaction(session):
                _audit(session, context, None, command, operation_id, "denied_after_io")
            raise

    dispatched_here = False

    def before_mutation():
        nonlocal dispatched_here, request_outcome
        with transaction(session):
            claimed = session.execute(update(SafeOperation).where(
                SafeOperation.id == operation_id, SafeOperation.state == "intent",
            ).values(state="dispatched")).rowcount
            if claimed != 1:
                request_outcome = "claim_lost"
                raise HTTPException(409, "Safe operation pending; retry reconciliation")
            _audit(session, context, object_id, command, operation_id, "dispatched")
        dispatched_here = True

    try:
        backend = Bao(settings)
        backend.operation_id = operation_id
        if mutation:
            with transaction(session):
                row = session.get(SafeOperation, operation_id)
                state, version = row.state, row.result_version
                session.expunge(row)
            if state == "intent" and command.action != "reconcile":
                # Configuration, source reads and AppRole login all happen
                # before the conditional committed dispatch immediately at POST.
                backend.before_mutation = before_mutation
                result = _perform(backend, locator, command, operation_id=operation_id)
                _finish(session, operation_id, "succeeded", result["version"])
            else:
                reconciled = True
                value = None
                completed = state == "succeeded"
                if state == "dispatched" or (completed and command.action == "write"):
                    state, version, value = _reconcile(backend, locator, row)
                    if not completed:
                        _finish(session, operation_id, state, version)
                if state != "succeeded":
                    raise HTTPException(409, "Safe operation outcome pending" if state in {
                        "intent", "dispatched"} else "Safe operation did not succeed")
                if command.action == "write" and _value(value) != {
                        "fields": command.fields, "preset": command.preset, "deleted": False}:
                    request_outcome = "payload_mismatch"
                    raise HTTPException(409, "Safe operation payload differs from completed write")
                result = {"version": version}
        else:
            result = _perform(backend, locator, command, operation_id=operation_id)
    except HTTPException as exc:
        if mutation and dispatched_here and exc.status_code in {404, 409, 422, 428}:
            _finish(session, operation_id, "conflict" if exc.status_code == 409 else "failed")
        else:
            with transaction(session):
                row = session.get(SafeOperation, operation_id) if mutation else None
                if exc.status_code == 503:
                    outcome = "uncertain" if row and row.state == "dispatched" else "unavailable"
                elif exc.status_code == 409:
                    outcome = ("pending" if row and row.state in {"intent", "dispatched"}
                               else "conflict")
                else:
                    outcome = "rejected"
                _audit(session, context, object_id, command, operation_id,
                       request_outcome or outcome)
        after_io()
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        with transaction(session):
            row = session.get(SafeOperation, operation_id) if mutation else None
            outcome = "uncertain" if row and row.state == "dispatched" else "unavailable"
            _audit(session, context, object_id, command, operation_id, outcome)
        after_io()
        raise HTTPException(503, "Credential safe unavailable") from None
    after_io(success=True)
    return result


def _operation_identity(instance_id, context, command):
    # Separate actor-scoped caller IDs from derived legacy IDs. No value,
    # preset or secret fingerprint enters this deterministic metadata digest.
    binding = [instance_id, context.principal.id, context.channel]
    if command.operation_id is not None:
        binding += ["caller", command.operation_id]
    else:
        binding += ["legacy", command.action, command.cas, command.version]
    return hashlib.sha256(json.dumps(binding).encode()).hexdigest()


def _validate_mutation(command):
    if command.cas is None:
        raise HTTPException(428, "Safe CAS version required")
    if command.cas >= MAX_VERSIONS - 1:
        raise HTTPException(409, "Safe version limit reached")
    if command.action in {"restore", "undelete"} and command.version is None:
        raise HTTPException(422, "Source version required")
    if command.action == "write" and command.fields is None:
        raise HTTPException(422, "Named string fields required")


def _authorize(session, context, object_id, command):
    context = refresh_write_context(session, context, object_id=object_id)
    permission = (Permission.READ_REFERENCE_CONTENT
                  if command.action in {"read", "history"} else Permission.WRITE_REFERENCE_CONTENT)
    authorize_object_command(session, context, object_id=object_id, permission=permission)
    row = session.get(CatalogObject, object_id)
    if row.kind != "credential_reference" or json.loads(row.data_json).get("provider") != "safe":
        raise HTTPException(409, "Select the safe credential provider explicitly")
    return context, (row.instance_id, row.revision)


def _perform(backend, locator, command, *, operation_id=None):
    path = "blockwart/data/" + locator
    if command.action == "history":
        try:
            data = backend.request("GET", "blockwart/metadata/" + locator)["data"]
        except HTTPException as exc:
            if exc.status_code == 404:
                return {"current_version": 0, "versions": {}}
            raise
        if (type(data["current_version"]) is not int
                or not 0 <= data["current_version"] <= MAX_VERSIONS
                or not isinstance(data["versions"], dict)
                or any(not isinstance(v, dict) for v in data["versions"].values())):
            raise ValueError("invalid history")
        return {"current_version": data["current_version"], "versions": data["versions"]}
    if command.action == "read":
        suffix = "?version=" + str(command.version) if command.version else ""
        data = backend.request("GET", path + suffix)["data"]
        value = _value(data["data"])
        if value.get("deleted"):
            raise HTTPException(404, "Safe entry is deleted")
        result = {"version": _version(data["metadata"]["version"]), **value}
    else:
        if command.cas is None:
            raise HTTPException(428, "Safe CAS version required")
        if command.cas >= MAX_VERSIONS - 1:
            raise HTTPException(409, "Safe version limit reached")
        if command.action in {"restore", "undelete"}:
            if command.version is None:
                raise HTTPException(422, "Source version required")
            value = _value(backend.request(
                "GET", path + "?version=" + str(command.version),
            )["data"]["data"])
            if value.get("deleted"):
                raise HTTPException(409, "Source version is deleted")
            # Restore is broker-internal copying, never an implicit value read to a writer.
        elif command.action == "delete":
            # A CAS tombstone preserves history and avoids KV delete's non-CAS race.
            value = {"deleted": True}
        else:
            if command.fields is None:
                raise HTTPException(422, "Named string fields required")
            value = {"fields": command.fields, "preset": command.preset, "deleted": False}
        result = backend.request("POST", path, {
            "options": {"cas": command.cas}, "data": {**value, "operation_id": operation_id},
        })["data"]
        version = _version(result["version"])
        if version != command.cas + 1:
            raise ValueError("unexpected write version")
        result = {"version": version}
    return result


def _version(value):
    if type(value) is not int or not 1 <= value <= MAX_VERSIONS:
        raise ValueError("invalid version")
    return value


def _value(value):
    if not isinstance(value, dict) or type(value.get("deleted")) is not bool:
        raise ValueError("invalid entry")
    if value["deleted"]:
        return {"deleted": True}
    validated = SafeAction(action="write", fields=value["fields"],
                           preset=value.get("preset", "other"))
    if validated.fields is None:
        raise ValueError("invalid fields")
    return {"fields": validated.fields, "preset": validated.preset, "deleted": False}
