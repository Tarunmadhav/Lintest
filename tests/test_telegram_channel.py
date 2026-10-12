"""Telegram channel: HTTP success/failure, timeouts, escaping, payload."""

from __future__ import annotations

import json

import pytest
import requests

from lintest.alerts.base import Alert
from lintest.alerts.telegram import TelegramChannel
from lintest.config import TelegramConfig
from lintest.models import Severity


class FakeResponse:
    def __init__(self, status_code: int = 200, body="", raise_on_json=None):
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self._body = body
        self._raise_on_json = raise_on_json

    def json(self):
        if self._raise_on_json:
            raise self._raise_on_json
        if isinstance(self._body, str):
            return json.loads(self._body) if self._body else {}
        return self._body


@pytest.fixture()
def channel(monkeypatch):
    monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "TESTTOKEN")
    monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "-100")
    return TelegramChannel(TelegramConfig(), hostname="srv1")


def alert() -> Alert:
    return Alert(Severity.CRITICAL, "system.cpu", "cpu", "CPU usage 99%")


def patch_post(monkeypatch, outcome):
    calls = {}

    def fake_post(url, data=None, timeout=None):
        calls["url"] = url
        calls["data"] = data
        calls["timeout"] = timeout
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr("lintest.alerts.telegram.requests.post", fake_post)
    return calls


class TestDelivery:
    def test_successful_send(self, monkeypatch, channel):
        calls = patch_post(monkeypatch, FakeResponse(200, {"ok": True}))
        assert channel.send(alert()) is True
        assert calls["url"] == "https://api.telegram.org/botTESTTOKEN/sendMessage"
        assert calls["data"]["chat_id"] == "-100"
        assert calls["data"]["parse_mode"] == "HTML"
        assert calls["data"]["disable_web_page_preview"] is True
        assert "CPU usage 99%" in calls["data"]["text"]

    def test_timeout_returns_false(self, monkeypatch, channel):
        patch_post(monkeypatch, requests.Timeout("too slow"))
        assert channel.send(alert()) is False

    def test_connection_error_returns_false(self, monkeypatch, channel):
        patch_post(monkeypatch, requests.ConnectionError("no route"))
        assert channel.send(alert()) is False

    def test_http_error_returns_false(self, monkeypatch, channel):
        patch_post(monkeypatch, FakeResponse(500, "server error"))
        assert channel.send(alert()) is False

    def test_rate_limit_returns_false(self, monkeypatch, channel):
        patch_post(monkeypatch, FakeResponse(429, {"ok": False, "description": "Too Many Requests"}))
        assert channel.send(alert()) is False

    def test_api_ok_false_returns_false(self, monkeypatch, channel):
        patch_post(monkeypatch, FakeResponse(200, {"ok": False, "description": "chat not found"}))
        assert channel.send(alert()) is False

    def test_non_json_body_is_treated_as_success(self, monkeypatch, channel):
        patch_post(monkeypatch, FakeResponse(200, "<html>gateway</html>",
                                            raise_on_json=ValueError("not json")))
        assert channel.send(alert()) is True

    def test_timeout_value_is_passed_to_requests(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig(timeout_seconds=3.5))
        calls = patch_post(monkeypatch, FakeResponse(200, {"ok": True}))
        ch.send(alert())
        assert calls["timeout"] == 3.5

    def test_disabled_channel_never_posts(self, monkeypatch):
        def forbidden(*a, **k):  # pragma: no cover - must not be called
            raise AssertionError("disabled channel must not contact the API")
        monkeypatch.setattr("lintest.alerts.telegram.requests.post", forbidden)
        ch = TelegramChannel(TelegramConfig(enabled=False))
        assert ch.send(alert()) is False

    def test_missing_chat_id_disables_the_channel(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.delenv("LINTEST_TELEGRAM_CHAT_ID", raising=False)
        ch = TelegramChannel(TelegramConfig())
        assert ch.enabled is False
        assert ch.available is False

    def test_token_is_redacted_from_logs_on_failure(self, monkeypatch, caplog):
        """requests embeds the token-bearing URL in exception text -- never log it."""
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "12345:SECRET-TOKEN-VALUE")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig())
        patch_post(monkeypatch, requests.ConnectionError(
            "HTTPSConnectionPool: https://api.telegram.org/bot12345:SECRET-TOKEN-VALUE/sendMessage"))
        with caplog.at_level("WARNING", logger="lintest.alerts.telegram"):
            assert ch.send(alert()) is False
        assert "SECRET-TOKEN-VALUE" not in caplog.text
        assert "<bot-token>" in caplog.text

    def test_token_is_redacted_from_http_error_bodies(self, monkeypatch, caplog):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "12345:SECRET-TOKEN-VALUE")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig())
        patch_post(monkeypatch, FakeResponse(500, "token 12345:SECRET-TOKEN-VALUE rejected"))
        with caplog.at_level("WARNING", logger="lintest.alerts.telegram"):
            assert ch.send(alert()) is False
        assert "SECRET-TOKEN-VALUE" not in caplog.text

    def test_redact_leaves_unrelated_text_alone(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "tok")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig())
        assert ch._redact("no secret here") == "no secret here"

    def test_custom_env_variable_names(self, monkeypatch):
        monkeypatch.setenv("MY_BOT_TOKEN", "abc")
        monkeypatch.setenv("MY_CHAT", "7")
        ch = TelegramChannel(TelegramConfig(token_env="MY_BOT_TOKEN", chat_id_env="MY_CHAT"))
        assert ch.available is True


class TestFormatting:
    def test_html_escaping_of_all_dynamic_text(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig(parse_mode="HTML"), hostname="srv<1>")
        text = ch._format(Alert(Severity.WARNING, "system.ram", "r<a>", "5 < 6 & 7 > 4"))
        assert "&lt;a&gt;" in text
        assert "&lt;1&gt;" in text
        assert "&amp;" in text
        assert "<a>" not in text

    def test_critical_uses_the_red_emoji(self, channel):
        assert "\U0001F534" in channel._format(alert())

    def test_subject_and_check_are_included(self, channel):
        text = channel._format(alert())
        assert "system.cpu" in text and "[cpu]" in text and "srv1" in text

    def test_plain_mode_does_not_escape(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig(parse_mode=""))
        text = ch._format(Alert(Severity.OK, "a<b", "c>d", "plain"))
        assert "a<b" in text and "c>d" in text

    def test_plain_mode_sends_no_parse_mode_field(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig(parse_mode=""))
        calls = patch_post(monkeypatch, FakeResponse(200, {"ok": True}))
        ch.send(alert())
        assert "parse_mode" not in calls["data"]

    def test_markdown_v2_escapes_reserved_characters(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        ch = TelegramChannel(TelegramConfig(parse_mode="MarkdownV2"))
        text = ch._format(Alert(Severity.CRITICAL, "system.disk", "/", "disk / is 95.5% full!"))
        assert "95\\.5" in text
        assert "full\\!" in text

    def test_invalid_parse_mode_is_rejected_by_config(self, tmp_path):
        from lintest.config import ConfigError, load_config

        bad = tmp_path / "config.yaml"
        bad.write_text("alerts:\n  telegram:\n    parse_mode: Cursed\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="parse_mode"):
            load_config(str(bad))
