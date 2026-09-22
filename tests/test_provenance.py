from pif.context import Context, Origin
from pif.provenance import check_nonce_forgery, new_nonce, render


def test_data_spans_are_fenced_with_the_nonce():
    ctx = Context().system("sys").user("hello").data("untrusted content", origin=Origin("ticket", "1"))
    nonce = new_nonce()
    rendered = render(ctx, nonce)
    assert f"<<<UNTRUSTED-{nonce} origin=ticket:1>>>" in rendered
    assert f"<<<END-{nonce}>>>" in rendered
    assert "untrusted content" in rendered


def test_system_and_user_spans_are_not_fenced():
    ctx = Context().system("sys prompt").user("user text")
    nonce = new_nonce()
    rendered = render(ctx, nonce)
    assert "UNTRUSTED" not in rendered
    assert "sys prompt" in rendered
    assert "user text" in rendered


def test_two_requests_get_different_nonces():
    assert new_nonce() != new_nonce()


def test_nonce_forgery_is_flagged_as_critical_invariant():
    nonce = new_nonce()
    ctx = Context().data(f"here is the fence token: {nonce}", origin=Origin("web", "x"))
    findings = check_nonce_forgery(ctx, nonce)
    assert len(findings) == 1
    assert findings[0].invariant is True
    assert findings[0].rule == "nonce-forgery"


def test_no_forgery_finding_for_normal_data():
    nonce = new_nonce()
    ctx = Context().data("nothing suspicious here", origin=Origin("web", "x"))
    findings = check_nonce_forgery(ctx, nonce)
    assert findings == []
