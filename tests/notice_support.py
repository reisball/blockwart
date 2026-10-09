"""Shared fixtures for agent notice tests (Issue #106): seeding and a loopback receiver."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sqlalchemy.orm import Session

from blockwart.models import CatalogObject, ObjectGrant, Principal, ServiceToken
from blockwart.services.agent_notices import (
    create_agent_delivery_target,
    create_agent_notice_subscription,
)


def seed_notice_env(
    session: Session,
    *,
    route: str = "openclaw-agent:test-inbox",
    principal_id: str = "principal-agent",
    object_id: str = "svc-01",
    label: str = "Runtime API",
) -> dict[str, str]:
    """Seed one readable service, an active service account, a target, and a rule.

    The caller commits. Existing object/principal rows are reused so one test
    can seed several routes.
    """
    if session.get(CatalogObject, object_id) is None:
        session.add(
            CatalogObject(
                id=object_id,
                kind="service",
                label=label,
                status="active",
                lifecycle="active",
                health="healthy",
                summary="Service under release monitoring.",
                data_json='{"schema_version": 1}',
            )
        )
    if session.get(Principal, principal_id) is None:
        session.add(
            Principal(
                id=principal_id,
                principal_type="service_account",
                login=principal_id,
                display_name="Agent Bot",
                active=True,
            )
        )
        session.add(
            ServiceToken(
                id=f"token-{principal_id}",
                principal_id=principal_id,
                name="default",
                token_prefix="bw_test_1234",
                token_hash=(principal_id.encode().hex() + "a" * 64)[:64],
            )
        )
        session.flush()
        session.add(
            ObjectGrant(
                principal_id=principal_id,
                object_id=object_id,
                role="viewer",
                scope="subtree",
            )
        )
    session.flush()
    target = create_agent_delivery_target(
        session,
        principal_id=principal_id,
        label=f"inbox {route}",
        route=route,
        transport="openclaw_test_gateway",
    )
    subscription = create_agent_notice_subscription(
        session,
        event_type="release_update_available",
        scope="object",
        object_id=object_id,
        principal_id=principal_id,
        target_id=target.id,
    )
    return {"target_id": target.id, "subscription_id": subscription.id}


class LoopbackReceiver:
    """An idempotent fake OpenClaw gateway on 127.0.0.1 (never any other host).

    The first request for a ``delivery_id`` becomes one *visible* delivery.
    Every repeat is answered with the duplicate confirmation and never becomes
    a second visible delivery. ``drop_responses`` makes the receiver accept a
    delivery and then close the connection without answering (response loss).
    """

    def __init__(self, *, duplicate_status: int = 409, duplicate_body: dict | None = None) -> None:
        self.visible: list[dict] = []
        self.request_ids: list[str] = []
        self.drop_responses = 0
        self.fail_next = 0
        self._duplicate_status = duplicate_status
        self._duplicate_body = duplicate_body
        self._accepted: set[str] = set()
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib naming
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                delivery_id = body["delivery_id"]
                with receiver._lock:
                    receiver.request_ids.append(delivery_id)
                    if receiver.fail_next > 0:
                        receiver.fail_next -= 1
                        status, payload, drop = 503, b"{}", False
                    elif delivery_id in receiver._accepted:
                        status = receiver._duplicate_status
                        payload = json.dumps(
                            receiver._duplicate_body
                            if receiver._duplicate_body is not None
                            else {"status": "duplicate", "delivery_id": delivery_id}
                        ).encode("utf-8")
                        drop = False
                    else:
                        receiver._accepted.add(delivery_id)
                        receiver.visible.append(body)
                        status, payload = 200, b"{}"
                        drop = receiver.drop_responses > 0
                        if drop:
                            receiver.drop_responses -= 1
                if drop:
                    return  # connection closes with no response
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args) -> None:  # noqa: ANN002 - stdlib hook
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/notify"

    def __enter__(self) -> LoopbackReceiver:
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
