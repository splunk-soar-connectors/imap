# File: imap_consts.py
# Copyright (c) 2014-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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
IMAP_JSON_MSG_ID = "message_id"
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
IMAP_ERR_CONNECTING_TO_SERVER = "Error connecting to server"
IMAP_ERR_LISTING_FOLDERS = "Error listing folders"
IMAP_ERR_LOGGING_IN_TO_SERVER = "Error logging in to server"
IMAP_ERR_SELECTING_FOLDER = "Error selecting folder '{folder}'"
IMAP_GOT_LIST_FOLDERS = "Got folder listing"
IMAP_LOGGED_IN = "User logged in"
IMAP_SELECTED_FOLDER = "Selected folder '{folder}'"
IMAP_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
IMAP_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
IMAP_ERR_END_TIME_LT_START_TIME = "End time less than start time"
IMAP_ERR_MAILBOX_SEARCH_FAILED = "Mailbox search failed"
IMAP_ERR_MAILBOX_SEARCH_FAILED_RESULT = "Mailbox search failed, result: {result} data: {data}"
IMAP_FETCH_ID_FAILED = "Fetch for uuid: {muuid} failed, reason: {excep}"
IMAP_FETCH_ID_FAILED_RESULT = "Fetch for uuid: {muuid} failed, result: {result}, data: {data}"
IMAP_MSG_GETTING_EMAILS = "Getting {max_emails} events from uid {lower_muid} onwards (uids might not be contiguous)"

IMAP_MILLISECONDS_IN_A_DAY = 86400000
IMAP_NUMBER_OF_DAYS_BEFORE_ENDTIME = 10
IMAP_CONTENT_TYPE_MESSAGE = "message/rfc822"
IMAP_DEFAULT_ARTIFACT_COUNT = 100
IMAP_DEFAULT_CONTAINER_COUNT = 100
MAX_COUNT_VALUE = 4294967295
