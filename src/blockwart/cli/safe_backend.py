"""Standalone, standard-library-only supervisor for the optional OpenBao bundle."""
from __future__ import annotations

import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(os.environ.get("SAFE_CONTROL_DIR", "/control"))
URL = os.environ.get("SAFE_LOCAL_URL", "http://127.0.0.1:8200")
CONFIG = os.environ.get("SAFE_CONFIG", "/etc/openbao/config.hcl")
BINARY = os.environ.get("SAFE_BINARY", "/bin/bao")
SENTINEL = {"bootstrap": "blockwart-safe-v1"}
POLICY = """
path "blockwart/data/*" { capabilities = ["create", "update", "read"] }
path "blockwart/metadata/*" { capabilities = ["read"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
"""
MAINTENANCE_POLICY = """
path "sys/config/auditing/request-headers/x-blockwart-operation" {
  capabilities = ["read", "create", "update", "sudo"]
}
path "sys/storage/raft/configuration" { capabilities = ["read", "sudo"] }
path "sys/generate-root-token/*" { capabilities = ["read", "update", "delete", "sudo"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
"""
MAINTENANCE_ROLE = {
    "bind_secret_id": True, "secret_id_ttl": 0, "secret_id_num_uses": 0,
    "token_policies": ["blockwart-maintenance"], "token_no_default_policy": True,
    "token_ttl": 900, "token_max_ttl": 900, "token_explicit_max_ttl": 900,
    "token_period": 0, "token_num_uses": 0, "token_type": "service",
}
MAINTENANCE_PATH = "auth/approle/role/blockwart-maintenance"
MAX_VERSIONS = 2147483647
AUDIT_FILE = Path("/openbao/audit/audit.json")
AUDIT_MAX_BYTES = 10 * 1024 * 1024


def configure_audit(token):
    # Upstream supported header allowlist; never accept caller-supplied names.
    call("POST", "sys/config/auditing/request-headers/x-blockwart-operation",
         {"hmac": False}, token)
    save("audit.json", {"version": 1})


def rotate_audit(process):
    try:
        if AUDIT_FILE.stat().st_size < AUDIT_MAX_BYTES:
            return
        subprocess.run(["logrotate", "--force", "--state", "/openbao/audit/rotation.state",
                        "/etc/logrotate-safe.conf"], check=True, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.send_signal(signal.SIGHUP)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("safe_backend_audit_rotation_failed") from None



class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(method, path, body=None, token=None, timeout=5):
    request = Request(URL + "/v1/" + path,
                      data=json.dumps(body).encode() if body is not None else None,
                      headers={"Content-Type": "application/json", **(
                          {"X-Vault-Token": token} if token else {}
                      )}, method=method)
    with build_opener(ProxyHandler({}), NoRedirect).open(request, timeout=timeout) as response:
        raw = response.read(1048577)
        expected_length = response.headers.get("Content-Length")
        if expected_length is not None and len(raw) != int(expected_length):
            raise ValueError("incomplete response")
        if len(raw) > 1048576:
            raise ValueError("safe_backend_response_bound")
        result = json.loads(raw) if raw else {}
        if not isinstance(result, dict):
            raise ValueError("safe_backend_invalid_response")
        return result


def save(name, value):
    # Files live outside the catalog and OpenBao data volume; never stdout.
    temporary = ROOT / (name + ".tmp")
    with open(temporary, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(ROOT / name)
    sync_directory(temporary.parent)


def sync_directory(path):
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load(name):
    return json.loads((ROOT / name).read_text())


def wait_ready(process):
    for _ in range(600):
        if process.poll() is not None:
            raise RuntimeError("safe_backend_start_failed")
        try:
            status = call("GET", "sys/seal-status")
            if not status["initialized"]:
                return status
            if not status["sealed"]:
                call("GET", "sys/health")  # active, not merely unsealed standby
                return status
            time.sleep(0.1)
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("safe_backend_start_timeout")


def verify(token):
    data = call("GET", "blockwart/data/bootstrap", token=token)
    if data["data"]["data"] != SENTINEL:
        raise RuntimeError("safe_backend_persistence_check_failed")


def approle_token(auth):
    return call("POST", "auth/approle/login", auth)["auth"]["client_token"]


def maintenance_credentials():
    directory = ROOT / "operator"
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise RuntimeError("safe_backend_operator_directory_unsafe")
    sync_directory(ROOT)  # persist the operator directory entry before credential dispatch
    for name in ("maintenance.json", "maintenance.json.tmp"):
        path = directory / name
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.geteuid()):
                raise RuntimeError("safe_backend_operator_file_unsafe")
    return directory / "maintenance.json"


def verify_maintenance_login():
    maintenance_credentials()
    token = approle_token(load("operator/maintenance.json"))
    try:
        data = call("GET", "auth/token/lookup-self", token=token)["data"]
        if (data["policies"] != ["blockwart-maintenance"]
                or data.get("identity_policies") or not 0 < data["ttl"] <= 900
                or data["explicit_max_ttl"] != 900):
            raise RuntimeError("safe_backend_maintenance_token_mismatch")
        header = call("GET", "sys/config/auditing/request-headers/x-blockwart-operation",
                      token=token)["data"]
        if header["x-blockwart-operation"]["hmac"] is not False:
            raise RuntimeError("safe_backend_maintenance_header_mismatch")
        call("GET", "sys/storage/raft/configuration", token=token)
        call("GET", "sys/generate-root-token/attempt", token=token)
    finally:
        call("POST", "auth/token/revoke-self", {}, token)


def verify_maintenance_configuration(token):
    policy = call("GET", "sys/policies/acl/blockwart-maintenance", token=token)["data"]
    role = call("GET", MAINTENANCE_PATH, token=token)["data"]
    if (policy["policy"].strip() != MAINTENANCE_POLICY.strip()
            or any(role.get(key) != value for key, value in MAINTENANCE_ROLE.items())
            or role.get("secret_id_bound_cidrs") or role.get("token_bound_cidrs")):
        raise RuntimeError("safe_backend_maintenance_configuration_mismatch")
    auth = load("operator/maintenance.json")
    role_id = call("GET", MAINTENANCE_PATH + "/role-id", token=token)["data"]["role_id"]
    if role_id != auth["role_id"]:
        raise RuntimeError("safe_backend_maintenance_role_mismatch")
    secret = call("POST", MAINTENANCE_PATH + "/secret-id/lookup",
                  {"secret_id": auth["secret_id"]}, token)["data"]
    if (secret["secret_id_ttl"] != 0 or secret["secret_id_num_uses"] != 0
            or secret.get("cidr_list") or secret.get("token_bound_cidrs")):
        raise RuntimeError("safe_backend_maintenance_secret_mismatch")


def provision_maintenance(token):
    # Only new initialization envelopes opt in; never migrate an existing control set.
    if not (ROOT / "maintenance-required.json").exists():
        return
    credentials = maintenance_credentials()
    call("PUT", "sys/policies/acl/blockwart-maintenance", {"policy": MAINTENANCE_POLICY}, token)
    call("POST", MAINTENANCE_PATH, MAINTENANCE_ROLE, token)
    if not credentials.exists():
        role_id = call("GET", MAINTENANCE_PATH + "/role-id", token=token)["data"]["role_id"]
        # Persist the planned ID BEFORE dispatch. A lost response is reconciled by
        # lookup of this same ID, never by issuing another random backend SecretID.
        save("operator/maintenance.json", {"role_id": role_id, "secret_id": secrets.token_hex(32)})
    auth = load("operator/maintenance.json")
    existing = call("POST", MAINTENANCE_PATH + "/secret-id/lookup",
                    {"secret_id": auth["secret_id"]}, token)
    # Pinned 2.7.2 returns 204 (empty body) for an absent SecretID, not 404.
    if existing == {}:
        call("POST", MAINTENANCE_PATH + "/custom-secret-id",
             {"secret_id": auth["secret_id"], "ttl": 0, "num_uses": 0}, token)
    verify_maintenance_configuration(token)
    verify_maintenance_login()


def finalize_maintenance(token):
    if not (ROOT / "maintenance-required.json").exists():
        return
    # Re-read private files and prove a fresh login on every finalization, also
    # after a crash following successful initial-root revocation.
    verify_maintenance_login()
    try:
        call("GET", "auth/token/lookup-self", token=token)
    except HTTPError as exc:
        if exc.code != 403 or load("maintenance-verified.json") != {"version": 1}:
            raise
    else:
        verify_maintenance_configuration(token)
        save("maintenance-verified.json", {"version": 1})


def preserve_initialization():
    # One durable init envelope closes the root/stage split-write crash window.
    if not (ROOT / "init.json").exists():
        return
    result = load("init.json")
    recovery = {key: result[key] for key in ("recovery_keys", "recovery_keys_base64")
                if result.get(key)}
    if not recovery or not result.get("root_token"):
        raise RuntimeError("safe_backend_invalid_initialization")
    if result.get("blockwart_maintenance") == 1:
        save("maintenance-required.json", {"version": 1})
    save("recovery.json", recovery)
    save("root.json", result["root_token"])
    if not (ROOT / "stage.json").exists():
        save("stage.json", "initialized")
    (ROOT / "init.json").unlink()
    sync_directory(ROOT)


def bootstrap(process):
    status = wait_ready(process)
    if status["sealed"] and status["initialized"]:
        raise RuntimeError("safe_backend_sealed")
    if status["initialized"]:
        preserve_initialization()
    if (ROOT / "runtime/broker.json").exists():
        if not (ROOT / "audit.json").exists() or load("audit.json") != {"version": 1}:
            raise RuntimeError("safe_backend_audit_configuration_required")
        if not status["initialized"]:
            raise RuntimeError("safe_backend_state_missing")
        token = approle_token(load("runtime/broker.json"))
        verify(token)
        call("POST", "auth/token/revoke-self", {}, token)
        return False
    if (ROOT / "pending.json").exists():
        token = approle_token(load("pending.json"))
        verify(token)
        call("POST", "auth/token/revoke-self", {}, token)
        finalize_maintenance(load("root.json"))
        # The initial root may have been revoked just before a previous crash.
        try:
            call("POST", "auth/token/revoke-self", {}, load("root.json"))
        except HTTPError as exc:
            if exc.code != 403:
                raise
        (ROOT / "pending.json").replace(ROOT / "runtime/broker.json")
        sync_directory(ROOT / "runtime")
        sync_directory(ROOT)
        (ROOT / "root.json").unlink(missing_ok=True)
        save("stage.json", "ready")
        return False
    if not status["initialized"]:
        if any(item.name != "runtime" for item in ROOT.iterdir()) or any(
            (ROOT / "runtime").iterdir()
        ):
            raise RuntimeError("safe_backend_control_without_state")
        result = call("POST", "sys/init",
                      {"recovery_shares": 1, "recovery_threshold": 1}, timeout=90)
        result["blockwart_maintenance"] = 1
        save("init.json", result)
        preserve_initialization()
        wait_ready(process)
    if not (ROOT / "root.json").exists():
        raise RuntimeError("safe_backend_initialized_without_control")
    token = load("root.json")
    stage = load("stage.json")
    if stage == "mounting":
        # An interrupted/failed first write is never retried on a possibly bad KV mount (#4331).
        raise RuntimeError("safe_backend_incomplete_first_write")
    if stage == "initialized":
        mounts = call("GET", "sys/mounts", token=token)["data"]
        if "blockwart/" not in mounts:
            call("POST", "sys/mounts/blockwart", {"type": "kv", "options": {"version": "2"}}, token)
        elif mounts["blockwart/"].get("type") != "kv":
            raise RuntimeError("safe_backend_mount_mismatch")
        # Newly enabled KV-v2 mounts briefly reject all requests during setup.
        # Retry only value-free readiness reads, never the initial data write.
        for attempt in range(100):
            try:
                call("GET", "blockwart/config", token=token)
                break
            except HTTPError as exc:
                if exc.code not in {400, 503} or attempt == 99:
                    raise
                time.sleep(0.1)
        call("POST", "blockwart/config",
             {"cas_required": True, "max_versions": MAX_VERSIONS}, token)
        save("stage.json", "mounting")
        call("POST", "blockwart/data/bootstrap",
             {"options": {"cas": 0}, "data": SENTINEL}, token)
        save("stage.json", "sentinel")
        return True  # force a real server restart before accepting credentials
    if stage != "sentinel":
        raise RuntimeError("safe_backend_invalid_bootstrap_stage")
    verify(token)
    configure_audit(token)
    call("PUT", "sys/policies/acl/blockwart-broker", {"policy": POLICY}, token)
    if "approle/" not in call("GET", "sys/auth", token=token)["data"]:
        call("POST", "sys/auth/approle", {"type": "approle"}, token)
    provision_maintenance(token)
    call("POST", "auth/approle/role/blockwart",
         {"token_policies": ["blockwart-broker"], "token_no_default_policy": True,
          "token_ttl": "60s", "token_max_ttl": "60s", "secret_id_ttl": 0,
          "secret_id_num_uses": 0}, token)
    role_id = call("GET", "auth/approle/role/blockwart/role-id", token=token)["data"]["role_id"]
    secret_id = call(
        "POST", "auth/approle/role/blockwart/secret-id", {}, token,
    )["data"]["secret_id"]
    save("pending.json", {"role_id": role_id, "secret_id": secret_id})
    # Re-enter the recoverable finalization path; root is not runtime auth.
    return bootstrap(process)


def main():
    if sys.argv[1:] and not (len(sys.argv) == 3 and sys.argv[1] == "--configure-audit"):
        print("safe_backend_invalid_arguments", flush=True)
        raise SystemExit(2)
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    (ROOT / "runtime").mkdir(mode=0o700, exist_ok=True)
    if len(sys.argv) == 3 and sys.argv[1] == "--configure-audit":
        # Existing initialized installations: explicit offline/staged operator
        # provisioning; no reinitialization, secret migration, or retained token.
        try:
            configure_audit(json.loads(Path(sys.argv[2]).read_text()))
        except Exception:
            print("safe_backend_audit_configuration_failed", flush=True)
            raise SystemExit(1) from None
        return
    AUDIT_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    AUDIT_FILE.parent.chmod(0o700)
    process = None

    def stop(_signum, _frame):
        if process is not None:
            process.terminate()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while True:
            process = subprocess.Popen(
                [BINARY, "server", "-config=" + CONFIG],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if bootstrap(process):
                process.terminate()
                process.wait(timeout=15)
                continue
            print("safe_backend_ready", flush=True)
            while process.poll() is None:
                rotate_audit(process)
                time.sleep(1)
            raise SystemExit(process.returncode)
    except Exception as exc:
        if isinstance(exc, RuntimeError) and str(exc) == "safe_backend_audit_rotation_failed":
            print("safe_backend_audit_rotation_failed", flush=True)
        # Do not print raw urllib errors, tokens, initialization replies or secret data.
        print("safe_backend_unavailable", flush=True)
        raise SystemExit(1) from None
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
