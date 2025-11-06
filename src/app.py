# Copyright (c) 2016-2025 Splunk Inc.
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
#
import contextlib
import email
import hashlib
import imaplib
import socket
import time
from collections.abc import Iterator
from datetime import datetime, UTC
from email.header import decode_header, make_header
from pydantic import Field as PydanticField

from dateutil import tz
from imapclient import imap_utf7
from parse import parse
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams, Param, Params

from .imap_consts import (
    IMAP_CONNECTED_TO_SERVER,
    IMAP_ERROR_CONNECTING_TO_SERVER,
    IMAP_ERROR_CONNECTIVITY_TEST,
    IMAP_ERROR_LISTING_FOLDERS,
    IMAP_ERROR_LOGGING_IN_TO_SERVER,
    IMAP_ERROR_MESSAGE,
    IMAP_ERROR_SELECTING_FOLDER,
    IMAP_FETCH_ID_FAILED,
    IMAP_FETCH_ID_FAILED_RESULT,
    IMAP_GENERAL_ERROR_MESSAGE,
    IMAP_GOT_LIST_FOLDERS,
    IMAP_LOGGED_IN,
    IMAP_SELECTED_FOLDER,
    IMAP_SUCCESS_CONNECTIVITY_TEST,
    IMAP_VALIDATE_INTEGER_MESSAGE,
)
from .process_email import ProcessEmail, IMAP_APP_ID

logger = getLogger()


class Asset(BaseAsset):
    server: str = AssetField(required=True, description="Server IP/Hostname")
    auth_type: str = AssetField(
        required=False,
        description="Authentication Mechanism to Use",
        default="Basic",
        value_list=["Basic", "OAuth"],
    )
    username: str = AssetField(required=True, description="Username")
    password: str = AssetField(required=False, description="Password", sensitive=True)
    client_id: str = AssetField(required=False, description="OAuth Client ID")
    client_secret: str = AssetField(
        required=False, description="OAuth Client Secret", sensitive=True
    )
    auth_url: str = AssetField(
        required=False,
        description="OAuth Authorization URL",
        default="https://accounts.google.com/o/oauth2/auth",
    )
    token_url: str = AssetField(
        required=False,
        description="OAuth Token URL",
        default="https://oauth2.googleapis.com/token",
    )
    scopes: str = AssetField(
        required=False,
        description="OAuth API Scope (JSON formatted list)",
        default='["https://mail.google.com/"]',
    )
    folder: str = AssetField(
        required=False,
        description="Folder to ingest mails from (default is inbox)",
        default="inbox",
    )
    ingest_manner: str = AssetField(
        required=True,
        description="How to ingest",
        default="oldest first",
        value_list=["oldest first", "latest first"],
    )
    first_run_max_emails: float = AssetField(
        required=True,
        description="Maximum emails to poll first time for schedule and interval polling",
        default=2000.0,
    )
    max_emails: float = AssetField(
        required=True, description="Maximum emails to poll", default=100.0
    )
    use_ssl: bool = AssetField(required=False, description="Use SSL", default=False)
    extract_attachments: bool = AssetField(
        required=False, description="Extract Attachments", default=True
    )
    extract_urls: bool = AssetField(
        required=False, description="Extract URLs", default=True
    )
    extract_ips: bool = AssetField(
        required=False, description="Extract IPs", default=True
    )
    extract_domains: bool = AssetField(
        required=False, description="Extract Domain Names", default=True
    )
    extract_hashes: bool = AssetField(
        required=False, description="Extract Hashes", default=True
    )
    add_body_to_header_artifacts: bool = AssetField(
        required=False,
        description="Add email body to the Email Artifact",
        default=False,
    )


app = App(
    name="IMAP",
    app_type="email",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Generic",
    product_name="IMAP",
    publisher="Splunk",
    appid="9f2e9f72-b0e5-45d6-92a7-09ef820476c1",
    fips_compliant=True,
    asset_cls=Asset,
)


class ImapHelper:
    """Helper class to manage IMAP connections and operations"""

    def __init__(self, soar: SOARClient, asset: Asset):
        self.soar = soar
        self.asset = asset
        self._imap_conn = None
        self._state = {}
        self._rsh = None
        self._asset_id = None
        self._folder_name = None
        self._is_hex = False

    def debug_print(self, *args):
        """Debug print for ProcessEmail compatibility"""
        logger.debug(" ".join(str(arg) for arg in args))

    def get_app_id(self):
        """Return IMAP app ID for ProcessEmail compatibility"""
        return IMAP_APP_ID

    def _get_error_message_from_exception(self, e):
        """Get appropriate error message from the exception"""
        error_code = None
        error_message = IMAP_ERROR_MESSAGE

        logger.error(f"Error occurred: {e}")

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            logger.error(
                f"Error occurred while fetching exception information. Details: {e!s}"
            )

        if not error_code:
            error_text = f"Error Message: {error_message}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_text

    @staticmethod
    def validate_integers(parameter, key, allow_zero=False):
        """Validate if the parameter is a valid integer"""
        try:
            if not float(parameter).is_integer():
                raise ValueError(IMAP_VALIDATE_INTEGER_MESSAGE.format(key=key))
            parameter = int(parameter)
        except Exception as e:
            raise ValueError(IMAP_VALIDATE_INTEGER_MESSAGE.format(key=key)) from e

        if parameter < 0:
            raise ValueError(
                f"Please provide a valid non-negative integer value in the {key} parameter"
            )
        if not allow_zero and parameter == 0:
            raise ValueError(
                f"Please provide a positive integer value in the {key} parameter"
            )

        return parameter

    def _generate_oauth_string(self, username, access_token):
        """Generates an IMAP OAuth2 authentication string"""
        auth_string = f"user={username}\1auth=Bearer {access_token}\1\1"
        return auth_string

    def _connect_to_server(self, first_try=True):
        """Connect to the IMAP server"""
        is_oauth = self.asset.auth_type == "OAuth"
        use_ssl = self.asset.use_ssl
        server = self.asset.server

        socket.setdefaulttimeout(60)

        try:
            if is_oauth or use_ssl:
                self._imap_conn = imaplib.IMAP4_SSL(server)
            else:
                self._imap_conn = imaplib.IMAP4(server)
                with contextlib.suppress(Exception):
                    self._imap_conn.starttls()
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(
                    IMAP_ERROR_CONNECTING_TO_SERVER, error_text
                )
            ) from None

        logger.info(IMAP_CONNECTED_TO_SERVER)

        try:
            if is_oauth:
                auth_string = self._generate_oauth_string(
                    self.asset.username,
                    self._state.get("oauth_token", {}).get("access_token"),
                )
                result, _ = self._imap_conn.authenticate(
                    "XOAUTH2", lambda _: auth_string
                )
            else:
                result, _ = self._imap_conn.login(
                    self.asset.username, self.asset.password
                )
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            if first_try and is_oauth and "Invalid credentials" in error_text:
                self._interactive_auth_refresh()
                return self._connect_to_server(False)
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(
                    IMAP_ERROR_LOGGING_IN_TO_SERVER, error_text
                )
            ) from None

        if result != "OK":
            raise Exception(IMAP_ERROR_LOGGING_IN_TO_SERVER)

        logger.info(IMAP_LOGGED_IN)

        try:
            result, _ = self._imap_conn.list()
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(
                    IMAP_ERROR_LISTING_FOLDERS, error_text
                )
            ) from e

        logger.info(IMAP_GOT_LIST_FOLDERS)

        self._folder_name = self.asset.folder
        try:
            result, _ = self._imap_conn.select(
                f'"{imap_utf7.encode(self._folder_name).decode()}"', True
            )
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(
                    IMAP_ERROR_SELECTING_FOLDER.format(folder=self._folder_name),
                    error_text,
                )
            ) from e

        if result != "OK":
            raise Exception(
                IMAP_ERROR_SELECTING_FOLDER.format(folder=self._folder_name)
            )

        logger.info(IMAP_SELECTED_FOLDER.format(folder=self._folder_name))

    def _get_email_data(self, muuid, folder=None, is_diff=False):
        """Get email data from IMAP server"""
        if is_diff and folder:
            try:
                result, data = self._imap_conn.select(
                    f'"{imap_utf7.encode(folder).decode()}"', True
                )
            except Exception as e:
                error_text = self._get_error_message_from_exception(e)
                raise Exception(
                    IMAP_GENERAL_ERROR_MESSAGE.format(
                        IMAP_ERROR_SELECTING_FOLDER.format(folder=folder), error_text
                    )
                ) from e

            if result != "OK":
                raise Exception(IMAP_ERROR_SELECTING_FOLDER.format(folder=folder))

            logger.info(IMAP_SELECTED_FOLDER.format(folder=folder))

        try:
            (result, data) = self._imap_conn.uid(
                "fetch", muuid, "(INTERNALDATE RFC822)"
            )
        except TypeError:
            (result, data) = self._imap_conn.uid(
                "fetch", str(muuid), "(INTERNALDATE RFC822)"
            )
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            raise Exception(
                IMAP_FETCH_ID_FAILED.format(muuid=muuid, excep=error_text)
            ) from e

        if result != "OK":
            raise Exception(
                IMAP_FETCH_ID_FAILED_RESULT.format(
                    muuid=muuid, result=result, data=data
                )
            )

        if not data or not isinstance(data, list):
            raise Exception(
                f"Invalid data returned for email ID {muuid}: data is not a list or is empty"
            )

        if data[0] is None:
            raise Exception(f"Email with ID {muuid} not found")

        if not isinstance(data[0], tuple) or len(data[0]) < 2:
            raise Exception(f"Invalid data structure for email ID {muuid}: {data[0]}")

        try:
            email_data = data[0][1].decode("UTF-8")
        except UnicodeDecodeError:
            email_data = data[0][1].decode("latin1")
        data_time_info = data[0][0].decode("UTF-8")

        return email_data, data_time_info

    def _get_email_ids_to_process(self, max_emails, lower_id, manner):
        """Get list of email UIDs to process based on ingestion manner"""
        try:
            result, data = self._imap_conn.uid("search", None, f"UID {lower_id!s}:*")
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            raise Exception(f"Failed to get email IDs: {error_text}") from e

        if result != "OK":
            raise Exception(f"Failed to get email IDs. Server response: {data}")

        if not data or not data[0]:
            return []

        uids = [int(uid) for uid in data[0].split()]

        if len(uids) == 1 and uids[0] < lower_id:
            return []

        uids.sort()
        max_emails = int(max_emails)

        if manner == "latest first":
            return uids[-max_emails:]
        else:
            return uids[:max_emails]

    def _parse_and_create_artifacts(
        self, email_id, email_data, data_time_info, asset, config=None
    ):
        """Parse email and yield Container and Artifacts for ingestion using ProcessEmail"""
        epoch = int(time.mktime(datetime.now(tz=UTC).timetuple())) * 1000

        if data_time_info:
            parse_data = parse('{left_ignore}"{dt:tg}"{right_ignore}', data_time_info)

            if parse_data and "dt" in parse_data.named:
                dt = parse_data["dt"]
                dt.replace(tzinfo=tz.tzlocal())
                epoch = int(time.mktime(dt.timetuple())) * 1000

        if config is None:
            config = {
                "extract_attachments": asset.extract_attachments,
                "extract_domains": asset.extract_domains,
                "extract_hashes": asset.extract_hashes,
                "extract_ips": asset.extract_ips,
                "extract_urls": asset.extract_urls,
            }

        process_email = ProcessEmail()
        process_email._base_connector = self
        process_email._folder_name = self._folder_name
        process_email._is_hex = self._is_hex
        process_email._config = config

        ret_val, message, results = process_email._int_process_email(
            email_data, email_id, epoch
        )

        if not ret_val:
            logger.error(f"Failed to process email {email_id}: {message}")
            return

        for result in results:
            container_dict = result.get("container")
            if container_dict:
                yield Container(**container_dict)

            artifacts = result.get("artifacts", [])
            for artifact_dict in artifacts:
                if artifact_dict:
                    yield Artifact(**artifact_dict)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Test connectivity to IMAP server"""
    helper = ImapHelper(soar, asset)
    try:
        helper._connect_to_server()
        soar.set_message(IMAP_SUCCESS_CONNECTIVITY_TEST)
        logger.info(IMAP_SUCCESS_CONNECTIVITY_TEST)
    except Exception as e:
        error_msg = f"{IMAP_ERROR_CONNECTIVITY_TEST}: {e!s}"
        soar.set_message(error_msg)
        logger.error(error_msg)
        raise


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    """Poll for new emails and ingest as containers/artifacts"""
    helper = ImapHelper(soar, asset)
    helper._connect_to_server()

    state = app.actions_manager.ingestion_state

    is_poll_now = params.container_count is not None

    if is_poll_now:
        lower_id = 1
        max_emails = params.container_count if params.container_count > 0 else 100
    else:
        is_first_run = state.get("first_run", True)
        lower_id = state.get("next_muid", 1)
        max_emails = (
            int(asset.first_run_max_emails) if is_first_run else int(asset.max_emails)
        )

    email_ids = helper._get_email_ids_to_process(
        max_emails, lower_id, asset.ingest_manner
    )

    if not email_ids:
        logger.info("No new emails to ingest")
        return

    for email_id in email_ids:
        try:
            email_data, data_time_info = helper._get_email_data(email_id)

            yield from helper._parse_and_create_artifacts(
                email_id, email_data, data_time_info, asset
            )

        except Exception as e:
            logger.error(f"Error processing email {email_id}: {e}")
            continue

    if email_ids and not is_poll_now:
        state["next_muid"] = int(email_ids[-1]) + 1
        state["first_run"] = False


class GetEmailSummary(ActionOutput):
    """Summary output for get_email action"""

    container_id: int | None = None


class GetEmailParams(Params):
    id: str = Param(
        description="Message ID to get",
        required=False,
        primary=True,
        cef_types=["imap email id"],
        default="",
    )
    container_id: str = Param(
        description="Container ID to get email data from",
        required=False,
        primary=True,
        cef_types=["phantom container id"],
        default="",
    )
    folder: str = Param(
        description="Folder name of email to get(used when id is given as input)",
        required=False,
        default="",
    )
    ingest_email: bool = Param(
        description="Create container and artifacts", required=False, default=False
    )


class GetEmailOutput(ActionOutput):
    # Make all fields optional since not all emails have all headers
    message: str | None = None
    container_id: int | None = None
    ARC_Authentication_Results: str | None = PydanticField(
        None, alias="ARC-Authentication-Results"
    )
    ARC_Message_Signature: str | None = PydanticField(
        None, alias="ARC-Message-Signature"
    )
    ARC_Seal: str | None = PydanticField(None, alias="ARC-Seal")
    Accept_Language: str | None = PydanticField(
        None, example_values=["en-US"], alias="Accept-Language"
    )
    Authentication_Results: str | None = PydanticField(
        None, alias="Authentication-Results"
    )
    CC: str | None = PydanticField(None, example_values=["User <test@xyz.com>"])
    Content_Language: str | None = PydanticField(
        None, example_values=["en-US"], alias="Content-Language"
    )
    Content_Transfer_Encoding: str | None = PydanticField(
        None, example_values=["quoted-printable"], alias="Content-Transfer-Encoding"
    )
    Content_Type: str | None = PydanticField(
        None,
        example_values=[
            'multipart/alternative; boundary="00000000000082bcbd056d5b9c37"'
        ],
        alias="Content-Type",
    )
    DKIM_Signature: str | None = PydanticField(None, alias="DKIM-Signature")
    Date: str | None = PydanticField(
        None, example_values=["Tue, 29 May 2018 17:31:58 +0000"]
    )
    Delivered_To: str | None = PydanticField(
        None, example_values=["test.user@hello.com"], alias="Delivered-To"
    )
    FCC: str | None = PydanticField(None, example_values=["test://user@19.2.4.2/Sent"])
    Feedback_ID: str | None = PydanticField(None, alias="Feedback-ID")
    From: str | None = PydanticField(
        None, example_values=["The Test Team <test-noreply@hello.test.com>"]
    )
    In_Reply_To: str | None = PydanticField(None, alias="In-Reply-To")
    MIME_Version: str | None = PydanticField(
        None, example_values=["1.0"], alias="MIME-Version"
    )
    Message_ID: str | None = PydanticField(
        None,
        example_values=[
            "<88f9844d75d4b351.1527615118220.110312844.20155287.en.630c09e415f69497@test.com>"
        ],
        alias="Message-ID",
    )
    Received: str | None = PydanticField(None)
    Received_SPF: str | None = PydanticField(None, alias="Received-SPF")
    References: str | None = PydanticField(None)
    Reply_To: str | None = PydanticField(
        None,
        example_values=["The Test Team <test-noreply@hello.test.com>"],
        alias="Reply-To",
    )
    Return_Path: str | None = PydanticField(
        None, cef_types=["email"], alias="Return-Path"
    )
    Subject: str | None = PydanticField(None, example_values=["Test Email Subject"])
    Thread_Index: str | None = PydanticField(
        None, example_values=["AdZLNWgVDiTd5bCtTtyx3vkNcc0vtQ=="], alias="Thread-Index"
    )
    Thread_Topic: str | None = PydanticField(
        None, example_values=["beep for 4.9!"], alias="Thread-Topic"
    )
    To: str | None = PydanticField(None, example_values=["test.user@hello.com"])
    User_Agent: str | None = PydanticField(None, alias="User-Agent")
    X_Account_Key: str | None = PydanticField(
        None, example_values=["account7"], alias="X-Account-Key"
    )
    X_Gm_Message_State: str | None = PydanticField(None, alias="X-Gm-Message-State")
    X_Google_DKIM_Signature: str | None = PydanticField(
        None, alias="X-Google-DKIM-Signature"
    )
    X_Google_Id: str | None = PydanticField(
        None, example_values=["194824"], alias="X-Google-Id"
    )
    X_Google_Smtp_Source: str | None = PydanticField(None, alias="X-Google-Smtp-Source")
    X_Identity_Key: str | None = PydanticField(
        None, example_values=["id1"], alias="X-Identity-Key"
    )
    X_MS_Exchange_Organization_AuthAs: str | None = PydanticField(
        None, example_values=["Internal"], alias="X-MS-Exchange-Organization-AuthAs"
    )
    X_MS_Exchange_Organization_AuthMechanism: str | None = PydanticField(
        None, example_values=["04"], alias="X-MS-Exchange-Organization-AuthMechanism"
    )
    X_MS_Exchange_Organization_AuthSource: str | None = PydanticField(
        None,
        example_values=["test1.test.com"],
        alias="X-MS-Exchange-Organization-AuthSource",
    )
    X_MS_Exchange_Organization_SCL: str | None = PydanticField(
        None, example_values=["-1"], alias="X-MS-Exchange-Organization-SCL"
    )
    X_MS_Has_Attach: str | None = PydanticField(None, alias="X-MS-Has-Attach")
    X_MS_TNEF_Correlator: str | None = PydanticField(None, alias="X-MS-TNEF-Correlator")
    X_Mozilla_Draft_Info: str | None = PydanticField(None, alias="X-Mozilla-Draft-Info")
    X_Received: str | None = PydanticField(None, alias="X-Received")


@app.action(
    description="Get an email from the server or container",
    action_type="investigate",
    verbose='Every container that is created by the IMAP app has the following values:<ul><li>The container ID, that is generated by the Phantom platform.</li><li>The Source ID that the app equates to the email ID along with the hash of the folder name on the remote server</li><li>The raw_email data in the container\'s data field is set to the RFC822 format of the email.</li></ul>This action parses email data and if specified, creates containers and artifacts. The email data to parse is either extracted from the remote server if an email <b>id</b> is specified along with its folder name or from a Phantom container if the <b>contianer_id</b> is specified. The folder parameter is used only when the email id is specified in the input. If the folder is not mentioned, it takes the folder name from the asset configuration parameter. If the folder name is not specified as an input of the \\"get email\\" action or in asset configuration parameters, \\"inbox\\" is taken as its value.<br>If both parameters are specified, the action will use the <b>container_id</b>.<br>Do note that any containers and artifacts created will use the label configured in the asset.',
)
def get_email(params: GetEmailParams, soar: SOARClient, asset: Asset) -> GetEmailOutput:
    """Get an email from the server or container"""
    if not params.id and not params.container_id:
        raise ValueError("Please specify either id or container_id to get the email")

    helper = ImapHelper(soar, asset)

    if params.id:
        helper._connect_to_server()
        folder = params.folder if params.folder else asset.folder
        email_data, _data_time_info = helper._get_email_data(
            params.id, folder, is_diff=True
        )

        folder_encoded = folder.encode()
        folder_hash = hashlib.sha256(folder_encoded)
        folder_hex = folder_hash.hexdigest()

        helper._is_hex = True
        helper._folder_name = folder_hex

        mail = email.message_from_string(email_data)

        mail_header_dict = {}
        headers = mail.__dict__.get("_headers", [])
        for header in headers:
            try:
                mail_header_dict[header[0]] = str(make_header(decode_header(header[1])))
            except Exception:
                process_email = ProcessEmail()
                mail_header_dict[header[0]] = process_email._decode_uni_string(
                    header[1], header[1]
                )

        data_time_info = _data_time_info
        if data_time_info is None:
            header_date = mail_header_dict.get("Date")
            if header_date is not None:
                data_time_info = f'ignore_left "{header_date}" ignore_right'

        container_id = None
        if params.ingest_email:
            config = {
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True,
            }

            containers_and_artifacts = list(
                helper._parse_and_create_artifacts(
                    params.id, email_data, data_time_info, asset, config=config
                )
            )

            for obj in containers_and_artifacts:
                if isinstance(obj, Container):
                    container_dict = obj.to_dict()
                    ret_val, message, cid = app.actions_manager.save_container(
                        container_dict
                    )
                    if ret_val:
                        container_id = cid
                    break

            if container_id:
                artifacts_to_save = []
                for obj in containers_and_artifacts:
                    if isinstance(obj, Artifact):
                        artifact_dict = obj.to_dict()
                        artifact_dict["container_id"] = container_id
                        artifacts_to_save.append(artifact_dict)
                if artifacts_to_save:
                    app.actions_manager.save_artifacts(artifacts_to_save)

            message = f"Email ingested with container ID: {container_id}"
            soar.set_summary(GetEmailSummary(container_id=container_id))
        else:
            message = "Email not ingested."

        soar.set_message(message)

        ret_val = {"message": message}
        if container_id:
            ret_val["container_id"] = container_id
        ret_val.update(mail_header_dict)

        return GetEmailOutput(**ret_val)

    if params.container_id:
        container = soar.get_container(params.container_id)
        if not container:
            raise ValueError(f"Container with ID {params.container_id} not found")

        soar.get_container_artifacts(params.container_id)

        ret_val = {}

        if container.get("data"):
            email_data = container["data"]
            if isinstance(email_data, dict):
                ret_val.update(email_data)

        return GetEmailOutput(**ret_val)

    raise ValueError("Please specify either id or container_id to get the email")


if __name__ == "__main__":
    app.cli()
