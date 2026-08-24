from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import read_only_transaction, transaction
from blockwart.services.identity import authenticate_bearer_header
from blockwart.services.login_protection import LoginProtector
from blockwart.services.read_access import ReadAccess, read_access_for_principal
from blockwart.services.token_failure_buckets import (
    TokenFailurePolicy,
    precheck_service_token_failure,
    prune_service_token_failure_buckets,
    record_service_token_failure,
    resolve_service_token_source,
    service_token_from_authorization,
)

bearer_scheme = HTTPBearer(auto_error=False)


def require_api_read_access(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> ReadAccess:
    authorization = (
        f"{credentials.scheme} {credentials.credentials}"
        if credentials is not None
        else None
    )
    settings = request.app.state.settings
    protector = request.app.state.login_protector
    if not isinstance(protector, LoginProtector):
        raise RuntimeError("Blockwart login protection is not initialized")
    request_id = getattr(request.state, "correlation_id", None)
    channel = (
        "mcp"
        if request.headers.get("X-Blockwart-Channel", "").casefold() == "mcp"
        else "api"
    )
    token = service_token_from_authorization(authorization)
    source = resolve_service_token_source(
        direct_peer=request.client.host if request.client is not None else None,
        forwarded_for=request.headers.getlist("X-Forwarded-For"),
        trusted_proxy_cidrs=settings.auth_trusted_proxy_cidrs,
    )
    policy = TokenFailurePolicy.from_settings(settings)
    with transaction(session):
        if protector.token_bucket_prune_due(
            interval_seconds=(
                settings.auth_service_token_failure_bucket_prune_interval_seconds
            )
        ):
            prune_service_token_failure_buckets(
                session,
                max_rows=policy.max_rows,
            )
        decision = precheck_service_token_failure(
            session,
            token=token,
            source=source,
            policy=policy,
            channel=channel,
            request_id=request_id,
        )
        principal = None
        if decision.allowed:
            principal = authenticate_bearer_header(
                session,
                authorization=authorization,
                channel=channel,
                request_id=request_id,
                record_failure_event=False,
            )
            if principal is None:
                record_service_token_failure(
                    session,
                    token=token,
                    source=source,
                    policy=policy,
                    channel=channel,
                    request_id=request_id,
                )
            else:
                access = read_access_for_principal(session, principal)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.read_access = access
    return access


def require_api_read_only_access(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> ReadAccess:
    """Authenticate one database-read-only API operation.

    A valid credential is verified against the same token, audience-neutral
    identity, failure-bucket, and object-policy state as every other v1 call,
    but its successful use does not update ``last_used_at`` or run maintenance.
    Invalid credentials deliberately fall through to the normal stateful
    authentication path so failure throttling and its bounded security
    evidence cannot be bypassed through a read-only endpoint.
    """
    authorization = (
        f"{credentials.scheme} {credentials.credentials}"
        if credentials is not None
        else None
    )
    settings = request.app.state.settings
    protector = request.app.state.login_protector
    if not isinstance(protector, LoginProtector):
        raise RuntimeError("Blockwart login protection is not initialized")
    request_id = getattr(request.state, "correlation_id", None)
    channel = (
        "mcp"
        if request.headers.get("X-Blockwart-Channel", "").casefold() == "mcp"
        else "api"
    )
    token = service_token_from_authorization(authorization)
    source = resolve_service_token_source(
        direct_peer=request.client.host if request.client is not None else None,
        forwarded_for=request.headers.getlist("X-Forwarded-For"),
        trusted_proxy_cidrs=settings.auth_trusted_proxy_cidrs,
    )
    policy = TokenFailurePolicy.from_settings(settings)
    principal = None
    with read_only_transaction(session):
        decision = precheck_service_token_failure(
            session,
            token=token,
            source=source,
            policy=policy,
            channel=channel,
            request_id=request_id,
            record_denial_event=False,
        )
        if decision.allowed:
            principal = authenticate_bearer_header(
                session,
                authorization=authorization,
                channel=channel,
                request_id=request_id,
                record_failure_event=False,
                update_last_used=False,
            )
            if principal is not None:
                access = read_access_for_principal(session, principal)
    if principal is None:
        # Preserve the established invalid-credential throttling, pruning, and
        # bounded security evidence. This path never reaches the preview.
        return require_api_read_access(request, credentials, session)
    request.state.read_access = access
    return access
