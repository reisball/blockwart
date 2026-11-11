"""Disposable root-container proofs for supervisor rotation and existing provisioning."""
from __future__ import annotations

import json
import time
from uuid import uuid4

# Runs only inside a disposable container. No output includes token files.
PROVISION = r'''
import json, os, subprocess, time
from pathlib import Path
import supervisor as s
os.umask(0o077)
s.ROOT.mkdir(parents=True, exist_ok=True)
(s.ROOT / "runtime").mkdir()
Path("/openbao/audit").mkdir(parents=True, exist_ok=True)
config = Path("/tmp/dev.hcl")
config.write_text('disable_mlock=true\naudit "file" "proof" { options { '
                  'file_path="/openbao/audit/audit.json" log_raw="false" mode="0600" } }')
p = subprocess.Popen(["/bin/bao", "server", "-dev", "-dev-root-token-id=synthetic-root",
    "-dev-listen-address=127.0.0.1:8200", "-config="+str(config)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def admin(method, path, body=None):
    return s.call(method, path, body, "synthetic-root")
try:
    s.wait_ready(p)
    admin("POST", "sys/mounts/blockwart", {"type":"kv", "options":{"version":"2"}})
    for attempt in range(100):
        try:
            admin("GET", "blockwart/config")
            break
        except Exception:
            time.sleep(.1)
    admin("POST", "blockwart/data/bootstrap", {"options":{"cas":0}, "data":s.SENTINEL})
    admin("POST", "sys/auth/approle", {"type":"approle"})
    admin("PUT", "sys/policies/acl/blockwart-broker", {"policy":s.POLICY})
    admin("POST", "auth/approle/role/blockwart", {"token_policies":["blockwart-broker"]})
    auth = {
        "role_id":admin("GET", "auth/approle/role/blockwart/role-id")["data"]["role_id"],
        "secret_id":admin("POST", "auth/approle/role/blockwart/secret-id", {})["data"]["secret_id"],
    }
    s.save("runtime/broker.json", auth)
    before = (s.ROOT/"runtime/broker.json").read_bytes()
    try:
        s.bootstrap(p)
        raise AssertionError("missing marker accepted")
    except RuntimeError as e:
        assert str(e) == "safe_backend_audit_configuration_required"
    endpoint = "sys/config/auditing/request-headers/x-blockwart-operation"
    tokenfile = s.ROOT/"temporary-admin.json"
    for sudo in (False, True):
        capabilities = '["create","update","sudo"]' if sudo else '["create","update"]'
        admin("PUT", "sys/policies/acl/audit-provision", {
            "policy":'path "'+endpoint+'" { capabilities='+capabilities+' }'})
        token = admin("POST", "auth/token/create", {
            "policies":["audit-provision"], "no_default_policy":True})["auth"]["client_token"]
        tokenfile.write_text(json.dumps(token))
        result = subprocess.run(["python", "/supervisor.py", "--configure-audit", str(tokenfile)],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == (0 if sudo else 1), result.stdout
        assert (s.ROOT/"audit.json").exists() == sudo
        admin("POST", "auth/token/revoke", {"token":token})
        tokenfile.unlink()
    assert s.load("audit.json") == {"version":1}
    assert s.bootstrap(p) is False
    assert (s.ROOT/"runtime/broker.json").read_bytes() == before
    assert admin("GET", "blockwart/data/bootstrap")["data"]["data"] == s.SENTINEL
    assert admin("GET", endpoint)["data"]["x-blockwart-operation"]["hmac"] is False
    assert not tokenfile.exists()
    print("existing_provisioning=passed default_loopback=verified "
          "sudo=required auth_data=unchanged")
finally:
    p.terminate()
    p.wait(timeout=10)
'''

READY = r'''
import json, os, urllib.request
from pathlib import Path
assert os.getuid() == 0
assert Path("/etc/logrotate-safe.conf").stat().st_mode & 0o777 == 0o644
auth = json.loads(Path("/control/runtime/broker.json").read_text())
def call(path, body=None, token=None):
    req=urllib.request.Request("http://127.0.0.1:8200/v1/"+path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type":"application/json", **({"X-Vault-Token":token} if token else {})})
    with urllib.request.urlopen(req, timeout=5) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}
token=call("auth/approle/login", auth)["auth"]["client_token"]
assert call("blockwart/data/bootstrap", token=token)["data"]["data"] == {
    "bootstrap":"blockwart-safe-v1"}
call("auth/token/revoke-self", {}, token)
p=Path("/openbao/audit/audit.json")
assert p.stat().st_uid == 0 and p.stat().st_mode & 0o777 == 0o600
assert p.parent.stat().st_mode & 0o777 == 0o700
'''


def prove(docker, image, repo):
    """Same root user as Compose; real main loop owns logrotate and SIGHUP."""
    name = "safe-supervisor-proof-" + uuid4().hex
    try:
        docker("run", "-d", "--name", name,
               "--tmpfs", "/openbao/data:mode=0700", "--tmpfs", "/control:mode=0700",
               "--tmpfs", "/openbao/audit:mode=0700", "--tmpfs", "/openbao/secrets:mode=0700",
               "-v", f"{repo / 'docs/credential-safe.hcl'}:/etc/openbao/config.hcl:ro",
               "--entrypoint", "sh", image, "-c",
               "umask 077; head -c 32 /dev/urandom >/openbao/secrets/unseal.key; "
               "exec python /supervisor.py")
        deadline = time.monotonic() + 90
        while "safe_backend_ready" not in docker("logs", name):
            assert json.loads(docker("inspect", name))[0]["State"]["Running"]
            assert time.monotonic() < deadline
            time.sleep(.2)
        docker("exec", name, "python", "-c", READY)
        for _ in range(9):
            # Trigger only by size: never invoke logrotate or send SIGHUP here.
            before = docker("exec", name, "python", "-c",
                            "from pathlib import Path; p=Path('/openbao/audit/audit.json'); "
                            "print(p.stat().st_ino); f=p.open('ab'); "
                            "f.truncate(10485760); f.close()")
            deadline = time.monotonic() + 20
            while True:
                current = docker("exec", name, "python", "-c",
                                 "from pathlib import Path; "
                                 "print(Path('/openbao/audit/audit.json').stat().st_ino)")
                if current != before:
                    break
                assert time.monotonic() < deadline, "supervisor did not rotate"
                time.sleep(.2)
            # A successful fresh operation must append to the new inode.
            docker("exec", name, "python", "-c", READY)
        docker("exec", name, "python", "-c",
               "from pathlib import Path; p=Path('/openbao/audit'); "
               "assert len(list(p.glob('audit.json.*')))==7; "
               "assert (p/'audit.json').stat().st_size>0; "
               "Path('/usr/sbin/logrotate').rename('/usr/sbin/logrotate.disabled'); "
               "f=(p/'audit.json').open('ab'); f.truncate(10485760); f.close()")
        deadline = time.monotonic() + 20
        while json.loads(docker("inspect", name))[0]["State"]["Running"]:
            assert time.monotonic() < deadline, "rotation fault did not stop supervisor/backend"
            time.sleep(.2)
        state = json.loads(docker("inspect", name))[0]["State"]
        assert state["ExitCode"] == 1
        logs = docker("logs", name)
        assert "safe_backend_audit_rotation_failed" in logs
        assert "safe_backend_unavailable" in logs
        assert "synthetic-root" not in logs
        # A stopped container has no surviving Bao process.
        assert docker("inspect", "--format", "{{.State.Pid}}", name) == "0"
        print("root_supervisor=passed rotations=9 retained=7 rotation_fault=stopped")
    finally:
        docker("rm", "-f", name)
    # Verify the actual helper against a running existing initialized backend
    # at its default 127.0.0.1:8200, with no retained administration token.
    docker("run", "--rm", "--tmpfs", "/control", "--tmpfs", "/openbao/audit",
           "--entrypoint", "python", image, "-c", PROVISION)
    print("existing_provisioning=passed default_loopback=verified "
          "sudo=required auth_data=unchanged")
