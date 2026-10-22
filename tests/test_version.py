from blockwart import __version__
from blockwart.main import create_app
from blockwart.mcp.server import SERVER_VERSION, server


def test_product_version_is_shared_by_api_and_mcp() -> None:
    app = create_app()

    assert app.version == __version__
    assert app.openapi()["info"]["version"] == __version__
    assert SERVER_VERSION == __version__
    assert server.version == __version__
