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

import ssl
from pathlib import Path


SOAR_CA_BUNDLE = Path("/opt/phantom/etc/cacerts.pem")


def create_ssl_context(verify_server_cert, ca_bundle=SOAR_CA_BUNDLE):
    """Create the TLS context used before sending IMAP credentials."""
    context = ssl.create_default_context()
    if verify_server_cert:
        if ca_bundle.is_file():
            context.load_verify_locations(cafile=str(ca_bundle))
        return context

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
