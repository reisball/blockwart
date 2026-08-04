from blockwart.domain.comment_markdown import render_comment_source


def test_markdown_renderer_keeps_the_supported_formatting_contract() -> None:
    rendered = str(
        render_comment_source(
            "# Heading\n\n**bold** and *emphasis*\n\n"
            "- one\n- two\n\n> quoted\n\n"
            "[safe](https://example.com/path) and `inline`\n\n"
            "```python\nprint('safe')\n```",
            "markdown",
        )
    )

    assert "<h1>Heading</h1>" in rendered
    assert "<strong>bold</strong>" in rendered
    assert "<em>emphasis</em>" in rendered
    assert "<ul>" in rendered and "<li>one</li>" in rendered
    assert "<blockquote>" in rendered
    assert '<a href="https://example.com/path"' in rendered
    assert 'rel="noopener noreferrer nofollow"' in rendered
    assert "<code>inline</code>" in rendered
    assert "<pre><code>print('safe')" in rendered


def test_markdown_renderer_keeps_active_content_and_media_inert() -> None:
    rendered = str(
        render_comment_source(
            "<script>alert(1)</script>"
            '<img src="https://tracker.invalid/pixel">\n\n'
            "[js](javascript:alert(1)) "
            "[data](data:text/html;base64,PHNjcmlwdD4=) "
            "[file](file:///etc/passwd) "
            "[mail](mailto:ops@example.com)",
            "markdown",
        )
    )

    assert "<script" not in rendered
    assert "<img" not in rendered
    assert "javascript:" in rendered
    assert 'href="javascript:' not in rendered
    assert 'href="data:' not in rendered
    assert 'href="file:' not in rendered
    assert '<a href="mailto:ops@example.com"' in rendered
    assert 'rel="noopener noreferrer nofollow"' in rendered


def test_legacy_plain_text_is_escaped_without_markdown_interpretation() -> None:
    rendered = str(
        render_comment_source(
            "# not a heading\n<b>not HTML</b> & text",
            "plain_text",
        )
    )

    assert rendered == (
        "<p># not a heading<br>\n"
        "&lt;b&gt;not HTML&lt;/b&gt; &amp; text</p>"
    )
    assert "<h1>" not in rendered
    assert "<b>" not in rendered
