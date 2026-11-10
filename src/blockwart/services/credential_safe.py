"""Internal OpenBao broker. Secret payloads never enter catalog persistence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from blockwart.config import Settings
from blockwart.domain.auth import Permission
from blockwart.models import CatalogObject
from blockwart.services.audit import add_audit_event
from blockwart.services.commands import (
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
    action: Literal["read", "history", "write", "restore", "delete", "undelete"]
    version: int | None = Field(default=None, ge=1, le=MAX_VERSIONS)
    cas: int | None = Field(default=None, ge=0, lt=MAX_VERSIONS)
    fields: dict[str, str] | None = None
    preset: Literal["login", "token", "key", "other"] = "other"

    @model_validator(mode="after")
    def bounded_fields(self):
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
                headers={"Content-Type": "application/json", **(
                    {"X-Vault-Token": token} if token else {}
                )},
                method=method,
            )
            with build_opener(NoRedirect).open(request, timeout=5) as response:
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise ValueError("response bound")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            exc.close()
            # Never publish OpenBao error text, request documents or tokens.
            if exc.code == 404:
                raise HTTPException(404, "Safe version not found") from None
            if exc.code == 400:
                raise HTTPException(409, "Safe version conflict or invalid operation") from None
            raise HTTPException(503, "Credential safe unavailable") from None
        except (OSError, URLError, ValueError, TypeError):
            raise HTTPException(503, "Credential safe unavailable") from None

    def token(self):
        try:
            auth = json.loads(Path(self.auth_file).read_text())
            result = self.call("POST", "auth/approle/login", {
                "role_id": auth["role_id"], "secret_id": auth["secret_id"],
            })
            return result["auth"]["client_token"]
        except (OSError, ValueError, KeyError, TypeError):
            raise HTTPException(503, "Credential safe unavailable") from None

    def request(self, method, path, body=None):
        token = self.token()
        try:
            return self.call(method, path, body, token=token)
        finally:
            # Short-lived tokens also expire if revocation is unavailable.
            try:
                self.call("POST", "auth/token/revoke-self", {}, token=token)
            except HTTPException:
                pass


def operate(session: Session, context: WriteContext, settings: Settings,
            object_id: str, command: SafeAction) -> dict:
    # Same lock/refresh boundary as ordinary reference writes, also for reads.
    context = refresh_write_context(session, context, object_id=object_id)
    permission = (Permission.READ_REFERENCE_CONTENT
                  if command.action in {"read", "history"} else Permission.WRITE_REFERENCE_CONTENT)
    authorize_object_command(session, context, object_id=object_id, permission=permission)
    row = session.get(CatalogObject, object_id)
    if row.kind != "credential_reference" or json.loads(row.data_json).get("provider") != "safe":
        raise HTTPException(409, "Select the safe credential provider explicitly")
    # Server-owned instance identity survives edits, not delete/recreate.
    locator = hashlib.sha256(row.instance_id.encode()).hexdigest()
    backend = Bao(settings)
    path = "blockwart/data/" + locator
    if command.action == "history":
        try:
            data = backend.request("GET", "blockwart/metadata/" + locator)["data"]
        except HTTPException as exc:
            if exc.status_code == 404:
                return {"current_version": 0, "versions": {}}
            raise
        add_audit_event(
            session, object_id=object_id, action="credential_safe_history",
            actor=context.principal.id, details={"channel": context.channel},
        )
        return {"current_version": data["current_version"], "versions": data["versions"]}
    if command.action == "read":
        suffix = "?version=" + str(command.version) if command.version else ""
        data = backend.request("GET", path + suffix)["data"]
        value = data["data"]
        if value.get("deleted"):
            raise HTTPException(404, "Safe entry is deleted")
        result = {"version": data["metadata"]["version"], **value}
    else:
        if command.cas is None:
            raise HTTPException(428, "Safe CAS version required")
        if command.cas >= MAX_VERSIONS - 1:
            raise HTTPException(409, "Safe version limit reached")
        if command.action in {"restore", "undelete"}:
            if command.version is None:
                raise HTTPException(422, "Source version required")
            value = backend.request(
                "GET", path + "?version=" + str(command.version),
            )["data"]["data"]
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
            "options": {"cas": command.cas}, "data": value,
        })["data"]
        result = {"version": result["version"]}
    add_audit_event(session, object_id=object_id, action="credential_safe_" + command.action,
                    actor=context.principal.id, details={"channel": context.channel})
    return result
