"""Request-local schema metadata snapshots without a settings cache."""

import json
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from threading import Barrier

import pytest
from test_ui import client, session_factory  # noqa: F401

from blockwart import config
from blockwart.domain import ui_schema


def _write(path, label):
    fields = {
        key: {"labels": {}, "placeholders": {}, "required": False, "visible_in_detail": True}
        for key in ui_schema.UI_SCHEMAS["system"].fields
    }
    fields["hardware_storage"]["labels"] = {"en": label}
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "kinds": {
                    "system": {
                        "field_order": list(ui_schema.UI_SCHEMAS["system"].fields),
                        "fields": fields,
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def _label():
    return (
        ui_schema.get_ui_schema("system").field_overrides["hardware_storage"].localized_labels["en"]
    )


@pytest.mark.parametrize("path", ["/", "/?view=topology", "/?kind=system&q=brieftraeger"])
@pytest.mark.parametrize("configured", [False, True])
def test_index_loads_schema_configuration_once(client, monkeypatch, tmp_path, path, configured):  # noqa: F811
    """Bound schema Settings and file reads across the real query and rendering."""
    override = tmp_path / "overrides.json"
    if configured:
        _write(override, "Snapshot disk")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override) if configured else "")
    counts = {"settings": 0, "file": 0}
    real_settings = ui_schema.get_settings
    real_read = ui_schema._read_schema_overrides_document

    def settings():
        counts["settings"] += 1
        return real_settings()

    def read(path):
        counts["file"] += 1
        return real_read(path)

    monkeypatch.setattr(ui_schema, "get_settings", settings)
    monkeypatch.setattr(config, "get_settings", settings)
    monkeypatch.setattr(ui_schema, "_read_schema_overrides_document", read)
    for _ in range(2):
        counts.update(settings=0, file=0)
        response = client.get(path)
        assert response.status_code == 200
        assert "brieftraeger" in response.text
        assert counts == {"settings": 1, "file": int(configured)}
        assert ui_schema._render_schema_overrides.get() is None


def test_next_request_reads_changed_path_file_and_errors(client, monkeypatch, tmp_path):  # noqa: F811
    """A previous successful render must not mask new metadata or errors."""
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    _write(a, "First disk")
    _write(b, "Second disk")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(a))
    assert "First disk" in client.get("/").text
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(b))
    assert "Second disk" in client.get("/?view=topology").text
    _write(b, "Third disk")
    assert "Third disk" in client.get("/").text
    b.write_text("{bad", encoding="utf-8")
    assert client.get("/").status_code == 500
    assert ui_schema._render_schema_overrides.get() is None
    _write(b, "Recovered disk")
    assert "Recovered disk" in client.get("/").text


def test_nested_exception_and_unscoped_reads_stay_fresh(monkeypatch, tmp_path):
    """Nested/failed scopes restore the outer snapshot; unscoped reads reload."""
    path = tmp_path / "overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(path))
    _write(path, "Outer")
    with ui_schema.ui_schema_read_snapshot():
        assert _label() == "Outer"
        _write(path, "Inner")
        with pytest.raises(RuntimeError, match="injected"):
            with ui_schema.ui_schema_read_snapshot():
                assert _label() == "Inner"
                raise RuntimeError("injected")
        assert _label() == "Outer"
        path.write_text("bad", encoding="utf-8")
        with pytest.raises(ui_schema.SchemaOverridesError):
            with ui_schema.ui_schema_read_snapshot():
                pytest.fail("invalid snapshot must not enter")
        assert _label() == "Outer"
    assert ui_schema._render_schema_overrides.get() is None
    _write(path, "Fresh")
    assert _label() == "Fresh"
    _write(path, "Uncached")
    assert _label() == "Uncached"
    monkeypatch.setenv("BLOCKWART_BUILD_REVISION", "first")
    assert config.get_settings().build_revision == "first"
    monkeypatch.setenv("BLOCKWART_BUILD_REVISION", "second")
    assert config.get_settings().build_revision == "second"


def test_dotenv_changes_are_seen_by_next_scope(monkeypatch, tmp_path):
    """Retain normal dotenv resolution rather than environment-only lookup."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", raising=False)
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    _write(a, "Dotenv A")
    _write(b, "Dotenv B")
    for path, expected in ((a, "Dotenv A"), (b, "Dotenv B")):
        (tmp_path / ".env").write_text(f"BLOCKWART_SCHEMA_OVERRIDES_PATH={path}", encoding="utf-8")
        with ui_schema.ui_schema_read_snapshot():
            assert _label() == expected


def test_concurrent_scopes_do_not_share_snapshot(monkeypatch, tmp_path):
    """Overlapping threads each retain only their own override document."""
    current_path = ContextVar("test_schema_path")
    barrier = Barrier(2)
    paths = [tmp_path / f"{i}.json" for i in range(2)]
    for i, path in enumerate(paths):
        _write(path, f"Thread {i}")
    monkeypatch.setattr(ui_schema, "_schema_overrides_path", current_path.get)

    def worker(i):
        token = current_path.set(paths[i])
        try:
            with ui_schema.ui_schema_read_snapshot():
                barrier.wait(timeout=5)
                assert _label() == f"Thread {i}"
                barrier.wait(timeout=5)
                assert _label() == f"Thread {i}"
            assert ui_schema._render_schema_overrides.get() is None
        finally:
            current_path.reset(token)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(worker, range(2)))


def test_render_exception_does_not_leave_snapshot(client, monkeypatch, tmp_path):  # noqa: F811
    """An exception during TemplateResponse rendering releases the scope."""
    from blockwart.ui import routes

    path = tmp_path / "overrides.json"
    _write(path, "Before failure")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(path))
    real_response = routes.templates.TemplateResponse

    def fail(*args, **kwargs):
        assert ui_schema._render_schema_overrides.get() is not None
        raise RuntimeError("render failed")

    monkeypatch.setattr(routes.templates, "TemplateResponse", fail)
    assert client.get("/").status_code == 500
    monkeypatch.setattr(routes.templates, "TemplateResponse", real_response)
    _write(path, "After failure")
    assert "After failure" in client.get("/").text
