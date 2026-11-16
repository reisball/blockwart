"""Shared section header contracts against real template sources and responses."""

import re
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from test_ui import client, session_factory  # noqa: F401

TEMPLATES = Path(__file__).parents[1] / "src/blockwart/ui/templates"


@pytest.mark.parametrize("name", ["index", "projects", "attention", "activity", "settings"])
def test_primary_sources_use_shared_header(name):
    """Require the reusable component, not six independent title implementations."""
    source = (TEMPLATES / f"{name}.html").read_text()
    assert '{% from "_section_header.html" import section_header %}' in source
    assert "<h1>" not in source
    assert "section_header(t(" in source
    assert 'href="/static/explorer.css' not in source or name == "index"
    if name == "index":
        topology = source.split('<main class="topology-shell section-page">')[1]
        assert topology.index('section_header(t("topology.title"))') < topology.index(
            'include "_local_search.html"'
        )
        assert 't("topology.eyebrow")' not in source
        assert "catalog.eyebrow" not in source
    if name == "settings":
        assert 't("detail.back")' not in source
        assert "settings.subtitle" not in source


@pytest.mark.parametrize(
    "url",
    ["/?view=catalog", "/?view=topology", "/projects", "/attention", "/activity", "/settings"],
)
def test_primary_responses_have_one_header_before_controls(client, url):  # noqa: F811
    """Preserve navigation and ensure title-first real response composition."""
    response = client.get(url)
    assert response.status_code == 200
    html = response.text
    assert html.count('class="section-header"') == 1
    assert len(re.findall(r"<h1(?:\s[^>]*)?>", html)) == 1
    assert html.index('class="main-header"') < html.index('class="section-header"')
    assert (
        html.index("<h1>") < html.index('class="section-header-actions"')
        if ('class="section-header-actions"' in html)
        else True
    )
    assert "data-smart-form" in html
    if "topology" in url:
        assert html.index("<h1>") < html.index("data-topology-search")
    if "catalog" in url:
        assert "data-visible-row-count" in html
        assert 'name="view" value="catalog"' in html


def test_shared_header_autoescapes_title_and_keeps_action_slot():
    """Reject unsafe plain-text titles while preserving caller markup and order."""
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape())
    template = env.from_string(
        '{% from "_section_header.html" import section_header %}'
        "{% call section_header(title) %}<button>Local action</button>{% endcall %}"
    )
    html = template.render(title="<script>unsafe</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert html.index("<h1>") < html.index("<button>")
