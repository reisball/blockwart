"""Browser grant previews must describe the selected role and actual reach."""
from __future__ import annotations

from contextlib import contextmanager
from html import unescape

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_responsibility_policy_320 import _object, _seed

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission
from blockwart.main import create_app
from blockwart.models import ObjectGrant
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
)
from blockwart.services.policy import policy_for_principal
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


@contextmanager
def _client(factory, *, role="owner", scope="responsibility", anchor="lxc", candidate_ids=None):
    with factory() as session, transaction(session):
        _seed(session)
        actor = create_human_principal(session, login="browser.responsible",
                                       display_name="Browser Responsible",
                                       password="browser-responsibility-test-password")
        create_object_grant(session, principal_id=actor.id, object_id=anchor,
                            role=role, scope=scope)
        if candidate_ids is not None:
            for name in ("first", "second"):
                candidate = create_service_account(
                    session, login=f"candidate.{name}", display_name=f"Candidate {name}",
                )
                candidate_ids.append(candidate.id)
        create_object_grant(session, principal_id=actor.id, object_id="service",
                            role="viewer", scope="self")
        browser = issue_browser_session(session, principal_id=actor.id, ttl_seconds=3600)
    app = create_app()

    def sessions():
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = sessions
    with TestClient(app) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
        yield client


def test_role_scope_preview_is_selected_and_existing_grants_keep_scope(alembic_session_factory):
    with _client(alembic_session_factory) as client:
        page = client.get('/objects/lxc', params={
            'edit': 'permissions', 'preview_role': 'owner', 'preview_scope': 'responsibility',
            'principal_q': 'browser',
        })
        assert page.status_code == 200, page.text
        assert 'data-grant-preview-selection>Owner · Full operational responsibility' in page.text
        assert 'data-grant-form data-grant-new data-responsibility-eligible="true"' in page.text
        preview = page.text.split('data-grant-preview-selection>', 1)[1].split('</ul>', 1)[0]
        assert all(identity in preview for identity in ('lxc', 'service', 'operations'))
        assert 'descriptive' not in preview
        assert 'value="responsibility" selected' in page.text
        page = client.get('/objects/service?edit=permissions')
        assert page.status_code == 200
        # Stored Viewer/self is not rewritten by a new Owner default.
        assert 'value="self" selected' in page.text
        assert 'value="viewer" selected' in page.text


@pytest.mark.parametrize("anchor", ["root", "lxc"])
@pytest.mark.parametrize("scope", ["self", "subtree"])
def test_new_host_owner_scope_preview_matches_saved_and_future_reach(
    alembic_session_factory, anchor, scope,
):
    factory = alembic_session_factory
    candidates = []
    expected = {anchor}
    if scope == "subtree":
        expected.update({"lxc", "service"})
    with _client(factory, anchor=anchor, scope="self", candidate_ids=candidates) as client:
        params = {
            "edit": "permissions",
            "principal_q": "candidate",
            "preview_principal": candidates[1],
            "preview_role": "owner",
        }
        if scope == "self":
            params["preview_scope"] = "self"
        page = client.get(f"/objects/{anchor}", params=params)
        assert page.status_code == 200, page.text
        new_form = page.text.split("data-grant-new", 1)[1].split("</form>", 1)[0]
        assert 'data-owner-default-scope="subtree"' in new_form
        assert 'value="owner" selected' in new_form
        assert f'value="{scope}" selected' in new_form
        assert f'value="{candidates[1]}" selected' in new_form
        assert "New Owner grants on hosts and systems" in page.text
        preview = page.text.split("data-grant-preview-selection>", 1)[1].split("</ul>", 1)[0]
        label = {"self": "This asset", "subtree": "Canonical subtree"}[scope]
        assert f"Owner · {label}" in preview
        for identity in ("root", "lxc", "service", "operations", "descriptive", "other", "ref"):
            assert (f'class="meta">{identity}' in preview) == (identity in expected)
        old_forms = page.text.split("data-grant-new", 1)[0]
        assert 'value="self" selected' in old_forms

        created = client.post(
            f"/objects/{anchor}/permissions/grants",
            data={
                "csrf_token": client.cookies[AUTH_CSRF_COOKIE_NAME],
                "if_match": page.headers["etag"],
                "principal_id": candidates[1],
                "role": "owner",
                "scope": scope,
            },
            follow_redirects=False,
        )
        assert created.status_code == 303, created.text

    with factory() as session, transaction(session):
        grant, = session.scalars(
            select(ObjectGrant).where(ObjectGrant.principal_id == candidates[1])
        ).all()
        assert (grant.object_id, grant.role, grant.scope) == (anchor, "owner", scope)
        before = policy_for_principal(session, candidates[1])
        session.add(_object("new-service", "service"))
        session.flush()
        create_relationship(
            session, from_ref="system:lxc", relation_type="hosts", to_ref="service:new-service",
        )
        after = policy_for_principal(session, candidates[1])
        for identity in ("root", "lxc", "service", "operations", "descriptive", "other", "ref"):
            permissions = set(Permission) if identity in expected else set()
            assert before.permissions_for(identity) == permissions
            assert after.permissions_for(identity) == permissions
        if scope == "subtree":
            source, = after.grants_for("new-service")
            assert source.grant_id == grant.id
            assert after.permissions_for("new-service") == set(Permission)
        else:
            assert not after.permissions_for("new-service")


def test_preview_cannot_silently_select_a_different_principal(alembic_session_factory):
    candidates = []
    with _client(alembic_session_factory, candidate_ids=candidates) as client:
        page = client.get("/objects/lxc", params={
            "edit": "permissions", "principal_q": "candidate", "preview_role": "owner",
            "preview_principal": "no-longer-in-results",
        })
        assert page.status_code == 200, page.text
        new_form = page.text.split("data-grant-new", 1)[1].split("</form>", 1)[0]
        assert '<option value="" selected disabled>Select a principal</option>' in new_form
        assert all(f'value="{candidate}" selected' not in new_form for candidate in candidates)


def test_preview_self_and_invalid_responsibility_query_cannot_show_subtree(
    alembic_session_factory,
):
    with _client(alembic_session_factory) as client:
        page = client.get('/objects/lxc?edit=permissions&preview_role=owner&preview_scope=self')
        assert page.status_code == 200
        preview = page.text.split('data-grant-preview-selection>', 1)[1].split('</ul>', 1)[0]
        assert 'Owner · This asset' in unescape(preview)
        assert 'operations' not in preview
        assert 'service' not in preview
        invalid = client.get(
            '/objects/lxc?edit=permissions&preview_role=editor&preview_scope=responsibility',
        )
        assert invalid.status_code == 200
        preview = invalid.text.split('data-grant-preview-selection>', 1)[1].split('</ul>', 1)[0]
        assert 'operations' not in preview
        assert 'value="responsibility" selected' not in invalid.text.split(
            'data-grant-preview-form', 1,
        )[1]


def test_owner_scope_change_events_preserve_old_grants_and_do_not_leak_csrf():
    """Execute the shipped JS change/click handlers, including the default transition."""
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for browser-event contract checks')
    source = Path('src/blockwart/ui/static/detail.js').resolve()
    program = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function fixture(roleValue, scopeValue, ownerDefaultScope, eligible = true) {
  const listeners = {};
  const option = {disabled:false};
  const role = {value:roleValue, addEventListener:(event, handler) => {listeners.role = handler;}};
  const scope = {
    value:scopeValue,
    querySelector:() => option,
    addEventListener:(event, handler) => {listeners.scope = handler;},
  };
  const button = {addEventListener:(event, handler) => {listeners.preview = handler;}};
  const save = {};
  const hint = {};
  const elements = {
    "[name='role'], [data-grant-role]": role,
    "[name='scope'], [data-grant-scope]": scope,
    "[data-preview-grant]": button,
    ...(ownerDefaultScope ? {
      "[data-save-grant]": save,
      "[data-preview-needed]": hint,
      "[name='principal_id']": {value:'chosen-principal'},
    } : {}),
  };
  const form = {
    dataset:{
      responsibilityEligible:String(eligible),
      ownerDefaultScope,
      previewRole:roleValue,
      previewScope:scopeValue,
    },
    querySelector:query => elements[query],
  };
  return {form, role, scope, option, listeners, save, hint};
}
const fresh = fixture('discoverer', 'self', 'subtree');
const unpreviewedSelf = fixture('owner', 'subtree', 'subtree');
const previewedSelf = fixture('owner', 'self', 'subtree');
const old = fixture('owner', 'self');
const service = fixture('discoverer', 'self', 'responsibility');
const otherKind = fixture('discoverer', 'self', 'self', false);
const forms = [fresh, unpreviewedSelf, previewedSelf, old, service, otherKind].map(f => f.form);
let destination;
const context = {
  URL,
  window:{location:{href:'https://example.invalid/objects/lxc?edit=permissions&principal_q=agent',
                   assign:value => {destination = value;}}},
  document:{querySelectorAll:query => query === '[data-grant-form]' ? forms : [],
            addEventListener:() => {}},
};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
assert.equal(old.scope.value, 'self');
old.role.value = 'viewer'; old.listeners.role();
old.role.value = 'owner'; old.listeners.role();
assert.equal(old.scope.value, 'self');
assert.equal(previewedSelf.scope.value, 'self');
assert.equal(previewedSelf.save.disabled, false);
previewedSelf.role.value = 'viewer'; previewedSelf.listeners.role();
previewedSelf.role.value = 'owner'; previewedSelf.listeners.role();
assert.equal(previewedSelf.scope.value, 'self');
assert.equal(previewedSelf.save.disabled, false);
assert.equal(fresh.option.disabled, true);
assert.equal(fresh.save.disabled, false);
fresh.role.value = 'owner'; fresh.listeners.role();
assert.equal(fresh.scope.value, 'subtree');
assert.equal(fresh.option.disabled, false);
assert.equal(fresh.save.disabled, true);
assert.equal(fresh.hint.hidden, false);
fresh.listeners.preview();
assert.equal(new URL(destination).searchParams.get('preview_scope'), 'subtree');
assert.equal(new URL(destination).searchParams.get('preview_role'), 'owner');
assert.equal(new URL(destination).searchParams.get('principal_q'), 'agent');
assert.equal(new URL(destination).searchParams.get('preview_principal'), 'chosen-principal');
assert.equal(new URL(destination).searchParams.has('csrf_token'), false);
fresh.role.value = 'editor'; fresh.listeners.role();
assert.equal(fresh.scope.value, 'self');
assert.equal(fresh.option.disabled, true);
unpreviewedSelf.scope.value = 'self'; unpreviewedSelf.listeners.scope();
assert.equal(unpreviewedSelf.save.disabled, true);
unpreviewedSelf.listeners.preview();
assert.equal(new URL(destination).searchParams.get('preview_scope'), 'self');
service.role.value = 'owner'; service.listeners.role();
assert.equal(service.scope.value, 'responsibility');
otherKind.role.value = 'owner'; otherKind.listeners.role();
assert.equal(otherKind.scope.value, 'self');
assert.equal(otherKind.option.disabled, true);
'''
    completed = subprocess.run([node, '-e', program, str(source)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("scope", ["responsibility", "subtree"])
def test_access_manager_browser_cannot_request_owner_preview(alembic_session_factory, scope):
    with _client(alembic_session_factory, role="access_manager", scope="self") as client:
        hidden = client.get('/objects/operations')
        assert hidden.status_code == 404
        page = client.get('/objects/lxc', params={
            'edit': 'permissions', 'preview_role': 'owner', 'preview_scope': scope,
        })
        assert page.status_code == 200
        preview = page.text.split('data-grant-preview-selection>', 1)[1].split('</ul>', 1)[0]
        assert 'operations' not in page.text
        assert 'Full operational responsibility' not in preview
        assert 'Discoverer' in preview
