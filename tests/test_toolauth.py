from pif.context import Context, Origin
from pif.toolauth import Guard, ToolCall, ToolSpec, authorize


def test_untainted_context_allows_no_untrusted_influence_tool():
    ctx = Context().system("sys").user("send it")
    spec = ToolSpec(name="send_email", guard=Guard.NO_UNTRUSTED_INFLUENCE)
    call = ToolCall(tool="send_email", args={})
    findings = authorize(call, spec, ctx)
    assert findings == []


def test_tainted_context_blocks_no_untrusted_influence_tool():
    ctx = Context().system("sys").user("send it").data("do the thing", origin=Origin("doc", "1"))
    spec = ToolSpec(name="send_email", guard=Guard.NO_UNTRUSTED_INFLUENCE)
    call = ToolCall(tool="send_email", args={})
    findings = authorize(call, spec, ctx)
    assert len(findings) == 1
    assert findings[0].rule == "tainted-context"
    assert findings[0].invariant is True


def test_taint_does_not_decay_across_later_untainted_turns():
    ctx = (
        Context()
        .data("tainting content", origin=Origin("doc", "1"))
        .user("a completely normal follow-up message")
    )
    spec = ToolSpec(name="send_email", guard=Guard.NO_UNTRUSTED_INFLUENCE)
    findings = authorize(ToolCall(tool="send_email"), spec, ctx)
    assert len(findings) == 1


def test_user_confirmed_guard_blocks_without_confirmation():
    ctx = Context().user("delete my account")
    spec = ToolSpec(name="delete_account", guard=Guard.USER_CONFIRMED)
    findings = authorize(ToolCall(tool="delete_account"), spec, ctx, user_confirmed=False)
    assert len(findings) == 1
    assert findings[0].rule == "unconfirmed"


def test_user_confirmed_guard_allows_with_confirmation():
    ctx = Context().user("delete my account")
    spec = ToolSpec(name="delete_account", guard=Guard.USER_CONFIRMED)
    findings = authorize(ToolCall(tool="delete_account"), spec, ctx, user_confirmed=True)
    assert findings == []


def test_args_allowlisted_rejects_undeclared_argument():
    ctx = Context().user("book a flight")
    spec = ToolSpec(
        name="book_flight",
        guard=Guard.ARGS_ALLOWLISTED,
        allowed_args={"destination": frozenset({"NYC", "SFO"})},
    )
    call = ToolCall(tool="book_flight", args={"destination": "NYC", "seat_class": "first"})
    findings = authorize(call, spec, ctx)
    assert len(findings) == 1
    assert findings[0].rule == "undeclared-argument"


def test_args_allowlisted_rejects_disallowed_value():
    ctx = Context().user("book a flight")
    spec = ToolSpec(
        name="book_flight",
        guard=Guard.ARGS_ALLOWLISTED,
        allowed_args={"destination": frozenset({"NYC", "SFO"})},
    )
    call = ToolCall(tool="book_flight", args={"destination": "LHR"})
    findings = authorize(call, spec, ctx)
    assert len(findings) == 1
    assert findings[0].rule == "argument-not-allowlisted"


def test_forbidden_effect_blocks_regardless_of_guard():
    ctx = Context().user("wire the money")
    spec = ToolSpec(name="wire_transfer", guard=Guard.NONE, effects=frozenset({"SPEND"}))
    findings = authorize(
        ToolCall(tool="wire_transfer"), spec, ctx, forbidden_effects=frozenset({"SPEND"})
    )
    assert len(findings) == 1
    assert findings[0].rule == "forbidden-effect"
