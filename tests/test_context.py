from pif.context import Context, Origin, Trust


def test_context_starts_untainted():
    ctx = Context().system("sys").user("hi")
    assert ctx.is_tainted is False
    assert ctx.tainted_by == ()


def test_adding_data_taints_the_context():
    ctx = Context().user("hi").data("stuff", origin=Origin("doc", "1"))
    assert ctx.is_tainted is True
    assert ctx.tainted_by == (Origin("doc", "1"),)


def test_context_is_immutable_append_only():
    base = Context().user("hi")
    branched = base.data("stuff", origin=Origin("doc", "1"))
    assert base.is_tainted is False
    assert branched.is_tainted is True
    assert len(base.spans) == 1
    assert len(branched.spans) == 2


def test_data_spans_carry_data_trust():
    ctx = Context().data("x", origin=Origin("doc", "1"))
    assert ctx.spans[0].trust is Trust.DATA
