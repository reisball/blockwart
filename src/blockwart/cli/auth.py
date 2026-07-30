from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.db.migrations import build_alembic_config, check_database_revision
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import GrantScope, PrincipalType, Role
from blockwart.models import (
    CatalogObject,
    ObjectGrant,
    PasswordCredential,
    Principal,
)
from blockwart.services.access import create_object_grant
from blockwart.services.identity import (
    IdentityConflict,
    IdentityError,
    create_human_principal,
    create_service_account,
    deactivate_principal,
    issue_service_token,
    principal_by_login,
    revoke_service_token,
    rotate_service_token,
    set_human_password,
    utc_now,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-auth",
        description="Manage Blockwart principals and credentials without exposing secrets.",
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL. Defaults to BLOCKWART_DATABASE_URL or local config.",
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    bootstrap = subparsers.add_parser(
        "bootstrap-owner",
        help="Create the first human principal and object Owner grant atomically.",
    )
    _add_human_fields(bootstrap)
    bootstrap.add_argument("--object-id", required=True)
    bootstrap.add_argument(
        "--scope",
        choices=tuple(scope.value for scope in GrantScope),
        default=GrantScope.SUBTREE,
    )

    create_human = subparsers.add_parser(
        "create-human",
        help="Create a local human principal.",
    )
    _add_human_fields(create_human)

    create_service = subparsers.add_parser(
        "create-service-account",
        help="Create a service-account principal without issuing a credential.",
    )
    create_service.add_argument("--login", required=True)
    create_service.add_argument("--display-name", required=True)

    for action in ("issue-token", "rotate-token"):
        token_parser = subparsers.add_parser(
            action,
            help=f"{action.replace('-', ' ').title()} for a service account.",
        )
        token_parser.add_argument("--login", required=True)
        token_parser.add_argument("--name", required=True)
        token_parser.add_argument("--output-file", type=Path, required=True)
        token_parser.add_argument(
            "--expires-in-seconds",
            type=int,
            default=None,
        )

    revoke = subparsers.add_parser(
        "revoke-token",
        help="Revoke one named service-account token.",
    )
    revoke.add_argument("--login", required=True)
    revoke.add_argument("--name", required=True)

    password = subparsers.add_parser(
        "set-password",
        help="Rotate one human password and revoke all browser sessions.",
    )
    password.add_argument("--login", required=True)
    password.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from one stdin line instead of an interactive prompt.",
    )

    deactivate = subparsers.add_parser(
        "deactivate-principal",
        help="Deactivate a principal and revoke all of its active credentials.",
    )
    deactivate.add_argument("--login", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_path: Path | None = getattr(args, "output_file", None)
    output_created = False
    engine = None
    try:
        check_database_revision(args.database_url)
        config = build_alembic_config(args.database_url)
        engine = build_engine(str(config.attributes["database_url"]))
        with Session(engine) as session:
            if args.action == "bootstrap-owner":
                result = _bootstrap_owner(session, args)
            elif args.action == "create-human":
                password = _read_password(args.password_stdin)
                with transaction(session):
                    principal = create_human_principal(
                        session,
                        login=args.login,
                        display_name=args.display_name,
                        password=password,
                    )
                result = (
                    "auth_create_human_ok "
                    f"principal_id={principal.id} login={principal.login}"
                )
            elif args.action == "create-service-account":
                with transaction(session):
                    principal = create_service_account(
                        session,
                        login=args.login,
                        display_name=args.display_name,
                    )
                result = (
                    "auth_create_service_account_ok "
                    f"principal_id={principal.id} login={principal.login}"
                )
            elif args.action in {"issue-token", "rotate-token"}:
                with transaction(session):
                    principal = principal_by_login(session, args.login)
                    if (
                        principal is None
                        or principal.principal_type != PrincipalType.SERVICE_ACCOUNT
                    ):
                        raise IdentityError("service account not found")
                    expires_at = _expiry(args.expires_in_seconds)
                    issued = (
                        issue_service_token(
                            session,
                            principal_id=principal.id,
                            name=args.name,
                            expires_at=expires_at,
                        )
                        if args.action == "issue-token"
                        else rotate_service_token(
                            session,
                            principal_id=principal.id,
                            name=args.name,
                            expires_at=expires_at,
                        )
                    )
                    _write_secret_file(output_path, issued.value)
                    output_created = True
                result = (
                    f"auth_{args.action.replace('-', '_')}_ok "
                    f"principal_id={issued.principal_id} credential_id={issued.token_id} "
                    f"output_file={output_path}"
                )
            elif args.action == "revoke-token":
                with transaction(session):
                    principal = principal_by_login(session, args.login)
                    if (
                        principal is None
                        or principal.principal_type != PrincipalType.SERVICE_ACCOUNT
                    ):
                        raise IdentityError("service account not found")
                    changed = revoke_service_token(
                        session,
                        principal_id=principal.id,
                        name=args.name,
                    )
                result = (
                    "auth_revoke_token_ok "
                    f"principal_id={principal.id} changed={int(changed)}"
                )
            elif args.action == "set-password":
                password = _read_password(args.password_stdin)
                with transaction(session):
                    principal = principal_by_login(session, args.login)
                    if (
                        principal is None
                        or principal.principal_type != PrincipalType.HUMAN
                    ):
                        raise IdentityError("human principal not found")
                    set_human_password(
                        session,
                        principal_id=principal.id,
                        password=password,
                    )
                result = (
                    "auth_set_password_ok "
                    f"principal_id={principal.id} sessions_revoked=all"
                )
            elif args.action == "deactivate-principal":
                with transaction(session):
                    principal = principal_by_login(session, args.login)
                    if principal is None:
                        raise IdentityError("principal not found")
                    changed = deactivate_principal(
                        session,
                        principal_id=principal.id,
                    )
                result = (
                    "auth_deactivate_principal_ok "
                    f"principal_id={principal.id} changed={int(changed)}"
                )
            else:
                raise IdentityError("unsupported auth action")
    except Exception:  # noqa: BLE001 - CLI boundary must redact credentials and DB details
        if output_created and output_path is not None:
            output_path.unlink(missing_ok=True)
        print(f"auth_{args.action.replace('-', '_')}_error=failed", file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()

    print(result)
    return 0


def _bootstrap_owner(session: Session, args: argparse.Namespace) -> str:
    existing = _bootstrap_state(
        session,
        login=args.login,
        display_name=args.display_name,
        object_id=args.object_id,
        scope=GrantScope(args.scope),
    )
    if existing is not None:
        principal, grant = existing
        return (
            "auth_bootstrap_owner_ok mode=unchanged "
            f"principal_id={principal.id} grant_id={grant.id} "
            f"object_id={grant.object_id} scope={grant.scope}"
        )

    principal_count = session.scalar(select(func.count()).select_from(Principal)) or 0
    grant_count = session.scalar(select(func.count()).select_from(ObjectGrant)) or 0
    if principal_count or grant_count:
        raise IdentityConflict("bootstrap state conflicts with existing identities or grants")
    if session.get(CatalogObject, args.object_id) is None:
        raise IdentityError("bootstrap object not found")

    password = _read_password(args.password_stdin)
    with transaction(session):
        principal_context = create_human_principal(
            session,
            login=args.login,
            display_name=args.display_name,
            password=password,
        )
        grant = create_object_grant(
            session,
            principal_id=principal_context.id,
            object_id=args.object_id,
            role=Role.OWNER,
            scope=GrantScope(args.scope),
            actor_principal_id=principal_context.id,
            channel="cli",
        )
    return (
        "auth_bootstrap_owner_ok mode=created "
        f"principal_id={principal_context.id} grant_id={grant.id} "
        f"object_id={grant.object_id} scope={grant.scope}"
    )


def _bootstrap_state(
    session: Session,
    *,
    login: str,
    display_name: str,
    object_id: str,
    scope: GrantScope,
) -> tuple[Principal, ObjectGrant] | None:
    try:
        principal = principal_by_login(session, login)
    except IdentityError:
        return None
    if principal is None:
        return None
    credential = session.get(PasswordCredential, principal.id)
    grant = session.scalar(
        select(ObjectGrant).where(
            ObjectGrant.principal_id == principal.id,
            ObjectGrant.object_id == object_id,
            ObjectGrant.role == Role.OWNER,
            ObjectGrant.scope == scope,
        )
    )
    if (
        principal.principal_type == PrincipalType.HUMAN
        and principal.active
        and principal.display_name == " ".join(display_name.split())
        and credential is not None
        and grant is not None
    ):
        return principal, grant
    raise IdentityConflict("bootstrap state is incomplete or conflicting")


def _add_human_fields(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--login", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from one stdin line instead of an interactive prompt.",
    )


def _read_password(from_stdin: bool) -> str:
    password = (
        sys.stdin.readline().rstrip("\r\n")
        if from_stdin
        else getpass.getpass("Password: ")
    )
    if not password:
        raise IdentityError("password is required")
    return password


def _expiry(seconds: int | None):
    if seconds is None:
        return None
    if seconds < 300 or seconds > 31536000:
        raise IdentityError("token expiry must be between 300 and 31536000 seconds")
    return utc_now() + timedelta(seconds=seconds)


def _write_secret_file(path: Path | None, value: str) -> None:
    if path is None:
        raise IdentityError("token output path is required")
    descriptor = None
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = None
            output.write(f"{value}\n")
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
