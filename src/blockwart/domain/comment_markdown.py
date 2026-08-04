from __future__ import annotations

from functools import lru_cache
from typing import Literal

import nh3
from markdown_it import MarkdownIt
from markupsafe import Markup, escape

CommentFormat = Literal["markdown", "plain_text"]

_ALLOWED_TAGS = {
    "a",
    "blockquote",
    "br",
    "code",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "ul",
}
_ALLOWED_ATTRIBUTES = {"a": {"href", "title"}}
_SAFE_URL_SCHEMES = {"http", "https", "mailto"}


@lru_cache(maxsize=1)
def _renderer() -> MarkdownIt:
    # Raw HTML stays disabled at the parser boundary. The independent sanitizer
    # remains mandatory so future Markdown features cannot silently widen HTML.
    return MarkdownIt("commonmark", {"html": False, "linkify": False})


def render_comment_source(body: str, format: CommentFormat) -> Markup:
    if format == "plain_text":
        return Markup("<p>") + escape(body).replace("\n", Markup("<br>\n")) + Markup("</p>")
    rendered = _renderer().render(body)
    sanitized = nh3.clean(
        rendered,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        url_schemes=_SAFE_URL_SCHEMES,
        link_rel="noopener noreferrer nofollow",
    )
    return Markup(sanitized)
