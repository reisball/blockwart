"""Real, disposable OpenBao proof; only synthetic values, never a live endpoint."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException

from blockwart.config import Settings
from blockwart.services.credential_safe import Bao


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True, timeout=180).stdout.strip()


def main():
    repo = Path(__file__).resolve().parents[2]
    image = "blockwart-safe-smoke:" + uuid4().hex
    name = "blockwart-safe-smoke-" + uuid4().hex
    created = False
    docker("build", "-f", str(repo / "Dockerfile.safe"), "-t", image, str(repo))
    try:
        from credential_safe_supervisor_smoke import prove
        prove(docker, image, repo)
        with tempfile.TemporaryDirectory(prefix="blockwart-safe-smoke-") as directory:
            root = Path(directory)
            for part in ("data", "control", "secrets", "audit"):
                (root / part).mkdir(mode=0o700)
            key = root / "secrets/unseal.key"
            key.write_bytes(os.urandom(32))
            key.chmod(0o600)
            docker("run", "-d", "--name", name, "--user", f"{os.getuid()}:{os.getgid()}",
                   "-p", "127.0.0.1::8200",
                   "-v", f"{root / 'data'}:/openbao/data",
                   "-v", f"{root / 'audit'}:/openbao/audit",
                   "-v", f"{root / 'control'}:/control",
                   "-v", f"{root / 'secrets'}:/openbao/secrets:ro",
                   "-v", f"{repo / 'docs/credential-safe.hcl'}:/etc/openbao/config.hcl:ro", image)
            created = True
            ports = json.loads(docker("inspect", name))[0]["NetworkSettings"]["Ports"]
            url = "http://127.0.0.1:" + ports["8200/tcp"][0]["HostPort"]
            auth = root / "control/runtime/broker.json"
            backend = Bao(Settings(safe_url=url, safe_auth_file=str(auth)))

            def ready():
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    observed = json.loads(docker("inspect", name))[0]
                    published = observed["NetworkSettings"]["Ports"].get("8200/tcp")
                    if published:
                        backend.url = "http://127.0.0.1:" + published[0]["HostPort"]
                    if auth.exists():
                        try:
                            assert backend.request("GET", "blockwart/data/bootstrap")["data"][
                                "data"] == {"bootstrap": "blockwart-safe-v1"}
                            return
                        except HTTPException:
                            pass
                    state = json.loads(docker("inspect", name))[0]["State"]
                    assert state["Running"], "Synthetic backend failed bootstrap"
                    time.sleep(0.2)
                raise AssertionError("Synthetic backend readiness timeout")

            ready()
            assert not (root / "control/root.json").exists()
            recovery = root / "control/recovery.json"
            assert recovery.stat().st_mode & 0o777 == 0o600
            assert json.loads(recovery.read_text())["recovery_keys_base64"]
            assert sorted(p.name for p in auth.parent.iterdir()) == ["broker.json"]
            assert set(json.loads(auth.read_text())) == {"role_id", "secret_id"}
            assert auth.stat().st_mode & 0o777 == 0o600
            path = "blockwart/data/synthetic-smoke"

            def put(cas, value):
                return backend.request("POST", path, {"options": {"cas": cas}, "data": value})

            backend.operation_id = uuid4().hex + uuid4().hex
            original = {"fields": {"key": "synthetic-key\nline2", "passphrase": "synthetic"},
                        "preset": "key", "deleted": False}
            assert put(0, original)["data"]["version"] == 1
            audit_file = root / "audit/audit.json"
            audit_rows = [json.loads(line) for line in audit_file.read_text().splitlines()]
            joined = [row for row in audit_rows if row.get("request", {}).get("headers", {}).get(
                "x-blockwart-operation") == [backend.operation_id]]
            assert {row["type"] for row in joined} == {"request", "response"}
            assert any(row["request"]["path"] == path for row in joined)
            assert "synthetic-key" not in audit_file.read_text()
            assert "synthetic-runtime" not in audit_file.read_text()
            assert audit_file.stat().st_mode & 0o777 == 0o600
            assert audit_file.parent.stat().st_mode & 0o777 == 0o700
            # Native denials retain the operation header even when the caller
            # cannot receive a successful backend response.
            try:
                backend.call("GET", path, token="synthetic-invalid-token")
                raise AssertionError("invalid token accepted")
            except HTTPException as exc:
                assert exc.status_code == 503
            denied = [json.loads(line) for line in audit_file.read_text().splitlines()]
            assert any(row.get("error") and row.get("request", {}).get("headers", {}).get(
                "x-blockwart-operation") == [backend.operation_id] for row in denied)

            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(put, 1, {"fields": {"token": f"synthetic-{i}"},
                                               "deleted": False}) for i in range(2)]
                outcomes = []
                for future in futures:
                    try:
                        outcomes.append(future.result()["data"]["version"])
                    except HTTPException as exc:
                        outcomes.append(exc.status_code)
            assert sorted(outcomes) == [2, 409]
            assert put(2, {"deleted": True})["data"]["version"] == 3
            assert backend.request("GET", path)["data"]["data"] == {"deleted": True}
            old = backend.request("GET", path + "?version=1")["data"]["data"]
            assert old == original
            assert put(3, old)["data"]["version"] == 4
            for forbidden in ("blockwart/destroy/synthetic-smoke", "sys/mounts/forbidden"):
                try:
                    backend.request("POST", forbidden, {"versions": [1]})
                except HTTPException as exc:
                    assert exc.status_code == 503
                else:
                    raise AssertionError("Broker policy allowed forbidden backend operation")
            history = backend.request("GET", "blockwart/metadata/synthetic-smoke")["data"]
            assert history["current_version"] == 4
            docker("restart", name)
            ready()
            assert backend.request("GET", path)["data"]["data"] == original
            # Missing static key fails closed. Restoring the same bytes automatically
            # unseals on next start without init, a root token, or operator unseal.
            docker("stop", name)
            key.rename(key.with_suffix(".saved"))
            docker("start", name)
            deadline = time.monotonic() + 30
            while json.loads(docker("inspect", name))[0]["State"]["Running"]:
                assert time.monotonic() < deadline
                time.sleep(0.1)
            try:
                backend.request("GET", path)
            except HTTPException as exc:
                assert exc.status_code == 503
            else:
                raise AssertionError("Missing seal key did not fail closed")
            key.with_suffix(".saved").rename(key)
            docker("start", name)
            ready()
            assert backend.request("GET", path)["data"]["data"] == original
            assert not (root / "control/root.json").exists()
            # Root mainloop proof above already verified rotation and pruning.
            # This separate nonroot scenario covers native sink failure/recovery.
            child_signal = ("import os,signal; "
                "p=next(int(x) for x in os.listdir('/proc') if x.isdigit() and "
                "open('/proc/'+x+'/comm').read().strip()=='bao'); os.kill(p,signal.SIGHUP)")
            assert backend.request("GET", path)["data"]["data"]["deleted"] is False
            # A directory at the native audit path forces reopen/append failure.
            # No second sink can mask the failure; restoring it recovers safely.
            fault_script = ("from pathlib import Path; p=Path('/openbao/audit/audit.json'); "
                            "p.rename(p.with_name('saved')); p.mkdir()")
            docker("exec", name, "python", "-c", fault_script)
            docker("exec", name, "python", "-c", child_signal)
            time.sleep(0.2)
            try:
                backend.request("GET", path)
                raise AssertionError("audit sink fault did not fail closed")
            except HTTPException as exc:
                assert exc.status_code == 503
            docker("exec", name, "python", "-c",
                   "from pathlib import Path; p=Path('/openbao/audit/audit.json'); "
                   "p.rmdir(); p.with_name('saved').rename(p)")
            docker("exec", name, "python", "-c", child_signal)
            ready()
            logs = docker("logs", name)
            assert "synthetic-key" not in logs
            docker("rm", "-f", name)
            created = False
        print("credential_safe_smoke=passed bootstrap=restart_verified cas=concurrent "
              "history=preserved soft_delete=cas_tombstone recover=passed "
              "missing_key=fail_closed restored_key=auto_unsealed broker=nonroot_policy")
    finally:
        if created:
            docker("rm", "-f", name)
        docker("image", "rm", image)


if __name__ == "__main__":
    main()
