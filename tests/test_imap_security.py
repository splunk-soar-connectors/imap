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

from imap_security import URI_REGEX, create_ssl_context


def test_verified_context_loads_platform_ca_bundle():
    context = MagicMock()
    ca_bundle = MagicMock()
    ca_bundle.is_file.return_value = True
    ca_bundle.__str__.return_value = "/opt/phantom/etc/cacerts.pem"

    with patch("imap_security.ssl.create_default_context", return_value=context):
        assert create_ssl_context(True, ca_bundle) is context

    context.load_verify_locations.assert_called_once_with(cafile="/opt/phantom/etc/cacerts.pem")


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
