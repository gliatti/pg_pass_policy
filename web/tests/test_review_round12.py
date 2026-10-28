"""Unit tests, twelfth review round: audit pagination without a useless
second query (the CSRF refusals and the reserved-name guard are tested in
round 13)."""

from __future__ import annotations

import pytest

from app import db
from tests.test_review_round3 import FakePool, _app
from tests.test_review_round3 import _client as _recording_client

# --- 2 / 3: one audit query when nothing matches -------------------------------------------


@pytest.mark.parametrize(("requested", "offsets"), [(5, [200]), (1, [0])])
def test_an_empty_audit_is_queried_once(monkeypatch, requested, offsets):
    events: list[str] = []
    app = _app()
    app.state.pool = FakePool(events)
    seen: list[int] = []

    def list_audit(conn, *, offset, limit, **kw):
        seen.append(offset)
        return [], 0

    monkeypatch.setattr(db, "list_audit", list_audit)
    client, _ = _recording_client(app, events)
    response = client.get("/audit/table", params={"page": str(requested)})
    assert response.status_code == 200
    assert seen == offsets
    assert "page 1 / 1" in response.text
