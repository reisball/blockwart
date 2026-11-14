"""Scoped product identity regressions; no authentication behavior changes."""

import hashlib
import json
from pathlib import Path

from test_ui import client, session_factory  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


def test_branding_assets_match_provenance():
    """Optimized copied assets retain the approved derivative hashes."""
    folder = ROOT / "src/blockwart/ui/static/branding"
    manifest = json.loads((folder / "provenance.json").read_text())
    assert len(manifest["files"]) == 10
    for item in manifest["files"]:
        data = (folder / item["name"]).read_bytes()
        assert len(data) == item["bytes"]
        assert hashlib.sha256(data).hexdigest() == item["sha256"]
    assert sum(item["bytes"] for item in manifest["files"]) < 400000


def test_header_settings_and_head_branding(client):  # noqa: F811
    """Header and About branding stay decorative and locally served."""
    for url in ["/", "/attention", "/activity", "/settings"]:
        page = client.get(url)
        assert page.status_code == 200
        assert 'src="/static/branding/blockwart-mark-40.png"' in page.text
        assert 'width="32" height="32" alt=""' in page.text
        assert 'href="/static/branding/favicon.ico"' in page.text
        assert 'class="auth-brand-hero"' not in page.text
    settings = client.get("/settings")
    assert 'id="settings-about-title"' in settings.text
    assert "https://github.com/reisball/blockwart" in settings.text
    assert settings.context["app_version"]
    assert "Über Blockwart" in client.get("/settings?lang=de").text


def test_login_hero_keeps_existing_security_form_contract():
    """Illustration is gated away from the active session and preserves inputs."""
    text = (ROOT / "src/blockwart/ui/templates/auth.html").read_text()
    assert "{% if not principal and login_challenge %}" in text
    assert 'name="login_challenge" value="{{ login_challenge }}"' in text
    assert 'name="csrf_token" value="{{ csrf_token }}"' in text
    assert 'action="/auth/login"' in text and 'action="/auth/logout"' in text
    assert 'width="1200" height="805" alt="" loading="lazy"' in text


def test_every_document_head_has_one_favicon_and_branding_after_app_css():
    """Render every document head to catch missing icons and cascade-order drift."""
    import re

    from jinja2 import Environment, FileSystemLoader

    folder = ROOT / "src/blockwart/ui/templates"
    environment = Environment(loader=FileSystemLoader(folder), autoescape=True)
    checked = []
    for template in sorted(folder.glob("*.html")):
        source = template.read_text()
        if "<head>" not in source:
            continue
        head = environment.from_string(source.split("</head>", 1)[0] + "</head>").render(
            locale="en",
            title="Fixture",
            t=lambda key, **kwargs: key,
            record={"short_code": "P-1", "data": {"title": "Fixture"}},
            object={"label": "Fixture"},
            project={"label": "Fixture"},
            ui_schemas={},
            explorer={"assets": []},
            create_fields_by_key={"relationship": {"label": "Parent"}},
            detail_query_string="",
            principal_scope="fixture",
            view="catalog",
            q="",
            kind="",
            selected_asset_ref="",
            object_kinds=["host"],
        )
        links = re.findall(r'<link [^>]*href="([^"]+)"[^>]*>', head)
        app = [i for i, href in enumerate(links) if href.startswith("/static/app.css")]
        branding = [i for i, href in enumerate(links) if href.startswith("/static/branding.css")]
        assert len(app) == len(branding) == 1, template.name
        assert app[0] < branding[0], template.name
        assert links.count("/static/branding/favicon.ico") == 1, template.name
        assert links.count("/static/branding/apple-touch-icon.png") == 1, template.name
        assert "data:," not in links, template.name
        checked.append(template.name)
    assert len(checked) >= 18
