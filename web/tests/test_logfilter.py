import logging

from app.logfilter import MASK, PasswordMaskFilter, install_log_masking, mask_text


def test_mask_text_patterns():
    assert mask_text("password=Hunter2!x") == f"password={MASK}"
    assert mask_text("PASSWORD 'Hunter2!x' and more") == f"PASSWORD '{MASK}' and more"
    assert (
        mask_text("conninfo: user=a password=S3cret host=h")
        == f"conninfo: user=a password={MASK} host=h"
    )
    assert mask_text("{'password': 'abc'}") == f"{{'password': '{MASK}'}}"
    assert mask_text("token: abcdef") == f"token: {MASK}"
    assert mask_text("nothing secret here") == "nothing secret here"


def test_filter_masks_message_args_and_extras():
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "rotated %s with %s", ("alice", {"password": "x"}), None
    )
    record.pwd = "clear"
    record.new_password = "clear"
    record.role = "alice"
    assert PasswordMaskFilter().filter(record)
    assert record.args[1] == {"password": MASK}
    assert record.pwd == MASK
    assert record.new_password == MASK
    assert record.role == "alice"
    assert record.getMessage() == f"rotated alice with {{'password': '{MASK}'}}"


def test_record_factory_masks_every_logger(caplog):
    install_log_masking()
    caplog.set_level(logging.DEBUG)
    logging.getLogger("some.third.party").warning("login failed password=Top-Secret-1")
    logging.getLogger("uvicorn.access").info("%s", {"password": "Top-Secret-2", "user": "bob"})
    assert "Top-Secret-1" not in caplog.text
    assert "Top-Secret-2" not in caplog.text
    assert MASK in caplog.text
    assert "bob" in caplog.text


def test_template_with_placeholder_is_masked_after_formatting(caplog):
    """'password=%s' is masked once formatted: the template is not masked
    alone (its argument would be left over, TypeError, line lost)."""
    install_log_masking()
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger("some.third.party")
    logger.warning("connect user=%s password=%s host=%s", "bob", "Top-Secret-3", "db1")
    assert "Top-Secret-3" not in caplog.text
    assert f"connect user=bob password={MASK} host=db1" in caplog.text
    record = caplog.records[-1]
    assert record.getMessage() == f"connect user=bob password={MASK} host=db1"


def test_placeholder_template_through_a_handler():
    """The line reaches a real handler's output (no formatting error)."""
    import io

    install_log_masking()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(PasswordMaskFilter())
    logger = logging.getLogger("pgpp_web.test.placeholder")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.error("token=%s for %s (%d tries)", "abcdef", "alice", 3)
    finally:
        logger.removeHandler(handler)
    assert stream.getvalue() == f"token={MASK} for alice (3 tries)\n"


def test_args_keep_their_types_when_nothing_is_secret():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "%s %d", ("GET", 200), None)
    assert PasswordMaskFilter().filter(record)
    assert record.msg == "%s %d" and record.args == ("GET", 200)
