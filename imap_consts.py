# File: imap_consts.py
#
# Copyright (c) 2016-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
IMAP_JSON_USE_SSL = "use_ssl"

IMAP_JSON_DATE = "date"
IMAP_JSON_FILES = "files"
IMAP_JSON_BODIES = "bodies"
IMAP_JSON_FROM = "from"
IMAP_JSON_MAIL = "mail"
IMAP_JSON_SUBJECT = "subject"
IMAP_JSON_TO = "to"
IMAP_JSON_START_TIME = "start_time"
IMAP_JSON_EXTRACT_ATTACHMENTS = "extract_attachments"
IMAP_JSON_EXTRACT_URLS = "extract_urls"
IMAP_JSON_EXTRACT_IPS = "extract_ips"
IMAP_JSON_EXTRACT_DOMAINS = "extract_domains"
IMAP_JSON_EXTRACT_HASHES = "extract_hashes"
IMAP_JSON_TOTAL_EMAILS = "total_emails"
IMAP_JSON_IPS = "ips"
IMAP_JSON_HASHES = "hashes"
IMAP_JSON_URLS = "urls"
IMAP_JSON_DOMAINS = "domains"
IMAP_JSON_EMAIL_ADDRESSES = "email_addresses"
IMAP_JSON_DEF_NUM_DAYS = "interval_days"
IMAP_JSON_MAX_EMAILS = "max_emails"
IMAP_JSON_FIRST_RUN_MAX_EMAILS = "first_run_max_emails"
IMAP_JSON_VAULT_IDS = "vault_ids"
IMAP_JSON_INGEST_MANNER = "ingest_manner"
IMAP_JSON_EMAIL_HEADERS = "email_headers"
IMAP_JSON_FOLDER = "folder"
IMAP_JSON_ID = "id"
IMAP_JSON_CONTAINER_ID = "container_id"
IMAP_JSON_INGEST_EMAIL = "ingest_email"

IMAP_INGEST_LATEST_EMAILS = "latest first"
IMAP_INGEST_OLDEST_EMAILS = "oldest first"

IMAP_CONNECTED_TO_SERVER = "Initiated connection to server"
IMAP_ERROR_CONNECTING_TO_SERVER = "Error connecting to server"
IMAP_ERROR_LISTING_FOLDERS = "Error listing folders"
IMAP_ERROR_LOGGING_IN_TO_SERVER = "Error logging in to server"
IMAP_ERROR_SELECTING_FOLDER = "Error selecting folder '{folder}'"
IMAP_GOT_LIST_FOLDERS = "Got folder listing"
IMAP_LOGGED_IN = "User logged in"
IMAP_SELECTED_FOLDER = "Selected folder '{folder}'"
IMAP_SUCCESS_CONNECTIVITY_TEST = "Connectivity test passed"
IMAP_ERROR_CONNECTIVITY_TEST = "Connectivity test failed"
IMAP_ERROR_END_TIME_LT_START_TIME = "End time less than start time"
IMAP_ERROR_MAILBOX_SEARCH_FAILED = "Mailbox search failed"
IMAP_ERROR_MAILBOX_SEARCH_FAILED_RESULT = "Mailbox search failed, result: {result} data: {data}"
IMAP_FETCH_ID_FAILED = "Fetch for uuid: {muuid} failed, reason: {excep}"
IMAP_FETCH_ID_FAILED_RESULT = "Fetch for uuid: {muuid} failed, result: {result}, data: {data}"
IMAP_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
IMAP_ERROR_CODE_MESSAGE = "Error code unavailable"
IMAP_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters"
IMAP_EXCEPTION_ERROR_MESSAGE = "Error Code: {0}. Error Message: {1}"
IMAP_REQUIRED_PARAM_OAUTH = "ERROR: {0} is a required parameter for OAuth Authentication, please specify one."
IMAP_REQUIRED_PARAM_BASIC = "ERROR: {0} is a required parameter for Basic Authentication, please specify one."
IMAP_GENERAL_ERROR_MESSAGE = "{}. Details: {}"
IMAP_STATE_FILE_CORRUPT_ERROR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)
IMAP_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
IMAP_DECRYPTION_ERROR = "Error occurred while decrypting the state file"

IMAP_MILLISECONDS_IN_A_DAY = 86400000
IMAP_NUMBER_OF_DAYS_BEFORE_ENDTIME = 10
IMAP_CONTENT_TYPE_MESSAGE = "message/rfc822"
IMAP_DEFAULT_ARTIFACT_COUNT = 100
IMAP_DEFAULT_CONTAINER_COUNT = 100
MAX_COUNT_VALUE = 4294967295
DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
