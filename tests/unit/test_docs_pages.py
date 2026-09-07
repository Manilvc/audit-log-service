"""The documentation pages must render behind a sub-path mount.

Both pages are served from this origin - `swagger-ui-dist` and ReDoc are
vendored under `app/static` - because an audit service tends to run where the
browser cannot reach a CDN. Two things have to hold for that to be true in
practice, and neither is visible from the route definitions:

* the CSP for those routes has to be the docs policy, not the strict API one;
* every asset URL has to carry the ASGI root_path.

Both failed in the shared-domain deployment (`--root-path /audit`), where the
page returned 200 and rendered blank: the CSP override keyed on "/docs" never
matched the request path, and the asset URLs resolved against the domain root,
which another service owns.

The mount is parameterised because the prefix reaches the app differently
depending on one character in the nginx config: `proxy_pass http://upstream;`
forwards "/audit/docs", while the same line with a trailing slash strips it and
the app sees "/docs". Both must work - the first is what production runs, and
it is the case the original fix still got wrong.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.middleware.stack import API_CSP
from app.main import DOCS_PATH, REDOC_PATH, app

#: The origins FastAPI's stock pages reach for, and the reason they are rebuilt.
FORBIDDEN_ORIGINS = ("cdn.jsdelivr.net", "fastapi.tiangolo.com", "fonts.googleapis.com")


@pytest.fixture
def container_stub() -> Iterator[None]:
    """Satisfy the rate-limit middleware without building a real container."""
    app.state.container = SimpleNamespace(redis=None)
    yield
    app.state.container = None


def _assets(html: str) -> list[str]:
    return sorted(set(re.findall(r'(?:src|href)="([^"]+)"', html)))


#: (root_path, prefix the proxy leaves on the request). The third case is
#: production: nginx forwards the full path and uvicorn is told the prefix.
MOUNTS = [("", ""), ("/audit", ""), ("/audit", "/audit")]


@pytest.mark.usefixtures("container_stub")
@pytest.mark.parametrize(("root_path", "prefix"), MOUNTS)
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_docs_page_renders_with_its_own_csp(root_path: str, prefix: str, path: str) -> None:
    """The strict API policy on a docs route is a blank page, not an error."""
    client = TestClient(app, root_path=root_path)
    response = client.get(f"{prefix}{path}")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert csp != API_CSP, (
        f"{prefix}{path} under root_path={root_path!r} got the API policy; its "
        "assets cannot load and the page renders blank"
    )
    assert "script-src 'self'" in csp


@pytest.mark.usefixtures("container_stub")
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_docs_pages_load_nothing_from_a_third_party(path: str) -> None:
    """Vendored, not CDN-loaded - the whole point of rebuilding these routes."""
    html = TestClient(app).get(path).text
    for origin in FORBIDDEN_ORIGINS:
        assert origin not in html, f"{path} still reaches for {origin}"


@pytest.mark.usefixtures("container_stub")
@pytest.mark.parametrize(("root_path", "prefix"), MOUNTS)
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_every_asset_a_docs_page_names_is_fetchable(root_path: str, prefix: str, path: str) -> None:
    """Each URL in the page resolves under the same mount that produced it.

    This is what catches a missing root_path: the page still renders, but its
    bundle 404s against the domain root and the page is blank.
    """
    client = TestClient(app, root_path=root_path)
    html = client.get(f"{prefix}{path}").text

    references = _assets(html)
    assert references, f"{path} referenced no assets at all"
    for reference in references:
        assert reference.startswith(f"{root_path}/"), (
            f"{path} points at {reference!r}, which ignores root_path={root_path!r}"
        )
        assert client.get(reference).status_code == 200, f"{reference} is not served"
