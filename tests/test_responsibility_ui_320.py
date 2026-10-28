"""Browser grant previews must describe the selected role and actual reach."""
from __future__ import annotations

from contextlib import contextmanager
from html import unescape

from fastapi.testclient import TestClient
from test_responsibility_policy_320 import _seed

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.services.access import create_object_grant
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


@contextmanager
def _client(factory):
    with factory() as session, transaction(session):
        _seed(session)
        actor = create_human_principal(session, login="browser.responsible",
                                       display_name="Browser Responsible",
                                       password="browser-responsibility-test-password")
        create_object_grant(session, principal_id=actor.id, object_id="lxc",
                            role="owner", scope="responsibility")
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

    import pytest

    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for browser-event contract checks')
    source = Path('src/blockwart/ui/static/detail.js').resolve()
    program = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function fixture(isNew, roleValue, scopeValue, eligible = true) {
  const listeners = {};
  const option = {disabled:false};
  const role = {value:roleValue, addEventListener:(event, handler) => {listeners.role = handler;}};
  const scope = {value:scopeValue, querySelector:() => option};
  const button = {addEventListener:(event, handler) => {listeners.preview = handler;}};
  const form = {
    dataset:{responsibilityEligible:String(eligible)},
    hasAttribute:() => isNew,
    querySelector:(query) => query.includes("name='role'") ? role :
      query.includes("name='scope'") ? scope : button,
  };
  return {form, role, scope, option, listeners};
}
const fresh = fixture(true, 'discoverer', 'self');
const old = fixture(false, 'owner', 'self');
const otherKind = fixture(true, 'owner', 'self', false);
const forms = [fresh, old, otherKind].map(f => f.form);
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
assert.equal(fresh.option.disabled, true);
fresh.role.value = 'owner'; fresh.listeners.role();
assert.equal(fresh.scope.value, 'responsibility');
assert.equal(fresh.option.disabled, false);
fresh.listeners.preview();
assert.equal(new URL(destination).searchParams.get('preview_scope'), 'responsibility');
assert.equal(new URL(destination).searchParams.get('preview_role'), 'owner');
assert.equal(new URL(destination).searchParams.get('principal_q'), 'agent');
assert.equal(new URL(destination).searchParams.has('csrf_token'), false);
fresh.role.value = 'editor'; fresh.listeners.role();
assert.equal(fresh.scope.value, 'self');
assert.equal(fresh.option.disabled, true);
assert.equal(otherKind.scope.value, 'self');
assert.equal(otherKind.option.disabled, true);
'''
    completed = subprocess.run([node, '-e', program, str(source)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
