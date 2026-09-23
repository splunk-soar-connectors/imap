# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import re
import ssl
from unittest.mock import MagicMock, patch

from imap_security import MAX_IMAP_UID, URI_REGEX, create_ssl_context, quote_imap_mailbox, validate_imap_uid


def _assert_value_error(function, value, expected_message):
    try:
        function(value)
    except ValueError as e:
        assert expected_message in str(e)
    else:
        raise AssertionError(f"Expected ValueError for {value!r}")


def test_validate_imap_uid_accepts_nonzero_32_bit_values():
    for uid in (1, "1", MAX_IMAP_UID, str(MAX_IMAP_UID)):
        assert validate_imap_uid(uid) == str(uid)


def test_validate_imap_uid_rejects_values_outside_rfc_3501_uniqueid_grammar():
    for uid in (None, True, 0, "0", -1, "-1", "01", "1.0", "1e2", " 1", "1 ", "\u0661", MAX_IMAP_UID + 1):
        _assert_value_error(validate_imap_uid, uid, "positive IMAP UID")


def test_quote_imap_mailbox_uses_modified_utf7_and_imap_quoted_string_escaping():
    assert quote_imap_mailbox('Team "A"\\B\u00fccher') == '"Team \\"A\\"\\\\B&APw-cher"'


def test_quote_imap_mailbox_rejects_line_terminators():
    for mailbox in ("INBOX\rCREATE injected", "INBOX\nCREATE injected", "INBOX\r\nCREATE injected"):
        _assert_value_error(quote_imap_mailbox, mailbox, "CR or LF")


def test_verified_context_loads_platform_ca_bundle():
    context = MagicMock()
    ca_bundle = MagicMock()
    ca_bundle.__str__.return_value = "/opt/phantom/etc/cacerts.pem"

    with patch("imap_security.ssl.create_default_context", return_value=context):
        assert create_ssl_context(True, ca_bundle) is context

    context.load_verify_locations.assert_called_once_with(cafile="/opt/phantom/etc/cacerts.pem")


def test_verified_context_uses_runtime_ca_bundle(monkeypatch):
    context = MagicMock()
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/splunk/broker/etc/cacerts.pem")

    with patch("imap_security.ssl.create_default_context", return_value=context):
        assert create_ssl_context(True) is context

    context.load_verify_locations.assert_called_once_with(cafile="/splunk/broker/etc/cacerts.pem")


def test_explicit_opt_out_disables_hostname_and_chain_validation():
    context = MagicMock()

    with patch("imap_security.ssl.create_default_context", return_value=context):
        assert create_ssl_context(False) is context

    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_url_expression_returns_complete_strings_for_ascii_and_idn_hosts():
    matches = re.findall(
        URI_REGEX,
        "See HTTPS://example.com/path and https://bücher.example/angebot",
    )

    assert matches == [
        "HTTPS://example.com/path",
        "https://bücher.example/angebot",
    ]
    assert all(isinstance(match, str) for match in matches)
