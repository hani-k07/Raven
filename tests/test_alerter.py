import pytest
import requests
from unittest.mock import patch, MagicMock
from alerter import check_and_alert, _send_telegram, _send_slack, _send_discord, _send_email

@patch("requests.post")
def test_send_telegram_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    import alerter
    alerter.TELEGRAM_BOT_TOKEN = "token"
    alerter.TELEGRAM_CHAT_ID = "id"

    assert _send_telegram("test") is True

@patch("requests.post")
def test_send_slack_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    import alerter
    alerter.SLACK_WEBHOOK_URL = "url"

    assert _send_slack("test") is True

@patch("requests.post")
def test_send_discord_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    import alerter
    alerter.DISCORD_WEBHOOK_URL = "url"

    assert _send_discord("test") is True

def test_send_email_no_host():
    import os
    os.environ["SMTP_HOST"] = ""
    assert _send_email("subj", "text") is False

def test_check_and_alert_empty(temp_db):
    # No threats in temp_db
    assert check_and_alert() == 0
