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

import os
import ssl
from pathlib import Path

from imapclient import imap_utf7


MAX_IMAP_UID = (1 << 32) - 1
URI_REGEX = (
    r"(?:[Hh][Tt][Tt][Pp][Ss]?:\/\/)(?:(?:[:@\.\-_0-9]|[^ -@\[-\`\{-\~\s]|"
    r"[\[\(][^\s\[\]\(\)]*[\]\)])+)(?:(?:[\/\?]+(?:[^\[\'\"\(\{\)\]\}\s]|[\[\(][^\[\]\(\)]*[\]\)])*)*)[\/]?"
)


def validate_imap_uid(value):
    """Return an RFC 3501 unique identifier in canonical string form."""
    uid = str(value)
    if not uid or not uid.isascii() or not uid.isdecimal() or uid[0] == "0" or int(uid) > MAX_IMAP_UID:
        raise ValueError(f"Email ID must be a positive IMAP UID between 1 and {MAX_IMAP_UID}")
    return uid


def quote_imap_mailbox(mailbox):
    """Encode and quote a mailbox name for an inline IMAP command argument."""
    if "\r" in mailbox or "\n" in mailbox:
        raise ValueError("Folder name must not contain CR or LF characters")

    encoded_mailbox = imap_utf7.encode(mailbox).decode("ascii")
    escaped_mailbox = encoded_mailbox.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped_mailbox}"'


def create_ssl_context(verify_server_cert, ca_bundle=None):
    """Create the TLS context used before sending IMAP credentials."""
    context = ssl.create_default_context()
    if verify_server_cert:
        ca_bundle = ca_bundle or Path(os.environ["REQUESTS_CA_BUNDLE"])
        context.load_verify_locations(cafile=str(ca_bundle))
        return context

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
