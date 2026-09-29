"""Telegram Bot API alert channel.

The bot token and chat id are **never** stored in config files -- they
are read from environment variables whose *names* are configured in
``alerts.telegram`` (defaults ``LINTEST_TELEGRAM_TOKEN`` and
``LINTEST_TELEGRAM_CHAT_ID``; see ``.env.example``).
"""

from __future__ import annotations

import html as _html
import logging
from typing import Optional

import requests

from lintest.alerts.base import Alert, AlertChannel
from lintest.config import TelegramConfig
from lintest.models import Severity

logger = logging.getLogger(__name__)

_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

_EMOJI = {
    Severity.CRITICAL: "\U0001F534",  # red circle
    Severity.WARNING: "\U0001F7E0",   # orange circle
    Severity.ERROR: "\U0001F7E3",     # purple circle
    Severity.INFO: "\U0001F7E2",      # green circle
    Severity.OK: "\U0001F7E2",
}


_BULLET = "\u2022"


class TelegramChannel(AlertChannel):
    """Sends alerts via the Telegram Bot API.  Failures are logged only."""

    name = "telegram"

    def __init__(self, cfg: TelegramConfig, hostname: str = "") -> None:
        self._cfg = cfg
        self._hostname = hostname
        self._token: Optional[str] = None
        self._chat_id: Optional[str] = None
        self.enabled = cfg.enabled
        if cfg.enabled:
            self._token = cfg.resolve_token()
            self._chat_id = cfg.resolve_chat_id()
            if not self._token or not self._chat_id:
                logger.warning(
                    "Telegram alerts enabled but %s / %s are not set in the "
                    "environment -- channel disabled", cfg.token_env, cfg.chat_id_env,
                )
                self.enabled = False

    @property
    def available(self) -> bool:
        """True when the channel is enabled and credentials are present."""
        return self.enabled and bool(self._token) and bool(self._chat_id)

    # -- formatting ---------------------------------------------------------

    def _escape(self, text: str) -> str:
        """Escape *text* for the configured parse mode (plain when empty)."""
        mode = self._cfg.parse_mode
        if mode == "HTML":
            return _html.escape(text, quote=False)
        if mode == "Markdown":
            for ch in ("_", "*", "`", "["):
                text = text.replace(ch, "\\" + ch)
            return text
        if mode == "MarkdownV2":
            for ch in ("_", "*", "[", "]", "(", ")", "~", "`", ">", "#",
                       "+", "-", "=", "|", "{", "}", ".", "!"):
                text = text.replace(ch, "\\" + ch)
            return text
        return text

    def _format(self, alert: Alert) -> str:
        head = _EMOJI.get(alert.severity, _BULLET) + " " + alert.severity.value
        if self._hostname:
            head += f" on {self._hostname}"
        subject = f" [{alert.subject}]" if alert.subject else ""
        body = f"{self._escape(alert.check)}{self._escape(subject)}\n{self._escape(alert.message)}"
        return f"{self._escape(head)}\n{body}"

    # -- delivery -----------------------------------------------------------

    def send(self, alert: Alert) -> bool:
        """POST the alert to the Telegram Bot API.  Never raises."""
        if not self.available:
            return False
        payload = {
            "chat_id": self._chat_id,
            "text": self._format(alert),
            "disable_web_page_preview": True,
        }
        if self._cfg.parse_mode:
            payload["parse_mode"] = self._cfg.parse_mode
        try:
            resp = requests.post(
                _API_URL.format(token=self._token),
                data=payload,
                timeout=self._cfg.timeout_seconds,
            )
        except requests.RequestException as exc:
            logger.warning("telegram send failed: %s", exc)
            return False
        if resp.status_code != 200:
            logger.warning("telegram send failed: HTTP %s %s",
                           resp.status_code, resp.text[:200])
            return False
        try:
            ok_flag = bool(resp.json().get("ok", True))
        except ValueError:
            ok_flag = True
        if not ok_flag:
            logger.warning("telegram API rejected the message: %s", resp.text[:200])
            return False
        return True
