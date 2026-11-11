import pytest


@pytest.mark.parametrize("path", ["/index.html", "/matrix.js"])
def test_matrix_network_and_crypto_allowed_by_page_policy(make_client, path):
    response = make_client().get(path)
    assert response.status_code == 200
    directives = {
        parts[0]: parts[1:]
        for directive in response.headers["Content-Security-Policy"].split(";")
        if (parts := directive.strip().split())
    }
    assert "https:" in directives["connect-src"]
    assert "wss:" in directives["connect-src"]
    assert "http://localhost:*" in directives["connect-src"]
    assert "http://127.0.0.1:*" in directives["connect-src"]
    assert "http://[::1]:*" in directives["connect-src"]
    assert "http:" not in directives["connect-src"]
    assert "*" not in directives["connect-src"]
    assert "'wasm-unsafe-eval'" in directives["script-src"]
    assert "'unsafe-eval'" not in directives["script-src"]
    assert "'unsafe-inline'" not in directives["script-src"]
    assert directives["script-src"][0] == "'self'"
    assert "microphone=(self)" in response.headers["Permissions-Policy"]
    assert "camera=(self)" in response.headers["Permissions-Policy"]
