# File: imap_connector.py
#
# Copyright (c) 2016-2023 Splunk Inc.
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
import base64
import email
import hashlib
import imaplib
import json
import os
import socket
import sys
import time
from builtins import str
from datetime import datetime, timedelta
from email.header import decode_header, make_header

import phantom.app as phantom
import requests
from dateutil import tz
from imapclient import imap_utf7
from parse import parse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from imap_consts import *
from process_email import ProcessEmail
from request_handler import RequestStateHandler, _get_dir_name_from_app_name


class ImapConnector(BaseConnector):

    ACTION_ID_GET_EMAIL = "get_email"

    def __init__(self):

        # Call the EmailConnector init first
        super(ImapConnector, self).__init__()

        self._imap_conn = None
        self._state_file_path = None
        self._state = {}
        self._preprocess_container = lambda x: x
        self._folder_name = None
        self._is_hex = False
        self._state = None
        self._rsh = None
        self._asset_id = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_message = IMAP_ERROR_MESSAGE

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.error_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_message)

        return error_text

    @staticmethod
    def validate_integers(action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param allow_zero: allowing zeros for integers
        :param key: parameter name
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """
        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, IMAP_VALIDATE_INTEGER_MESSAGE.format(key=key))
                return None
            parameter = int(parameter)

        except Exception:
            action_result.set_status(phantom.APP_ERROR, IMAP_VALIDATE_INTEGER_MESSAGE.format(key=key))
            return None

        if parameter < 0:
            action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {} parameter".format(key))
            return None
        if not allow_zero and parameter == 0:
            action_result.set_status(phantom.APP_ERROR, "Please provide a positive integer value in the {} parameter".format(key))
            return None

        return parameter

    def make_rest_call(self, action_result, url, verify=False):

        r = requests.get(url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
        if not r:
            message = 'Status Code: {0}'.format(r.status_code)
            if r.text:
                message = "{} Error from Server: {}".format(message, r.text.replace('{', '{{').replace('}', '}}'))
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving system info, {0}".format(message)), None

        try:
            resp_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error processing response JSON", e), None

        return phantom.APP_SUCCESS, resp_json

    def _get_phantom_base_url_imap(self, action_result):

        ret_val, resp_json = self.make_rest_call(action_result, '{}rest/system_info'.format(self.get_phantom_base_url()))

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        phantom_base_url = resp_json.get('base_url')
        if not phantom_base_url:
            return action_result.set_status(
                phantom.APP_ERROR, "Phantom Base URL is not configured, please configure it in System Settings"), None

        phantom_base_url = phantom_base_url.strip("/")

        return phantom.APP_SUCCESS, phantom_base_url

    def _get_asset_name(self, action_result):

        ret_val, resp_json = self.make_rest_call(
            action_result, '{}rest/asset/{}'.format(self.get_phantom_base_url(), self.get_asset_id()))

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving asset name"), None

        return phantom.APP_SUCCESS, asset_name

    def _get_url_to_app_rest(self, action_result=None):
        if not action_result:
            action_result = ActionResult()
        # get the phantom ip to redirect to
        ret_val, phantom_base_url = self._get_phantom_base_url_imap(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), action_result.get_message()
        # get the asset name
        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), action_result.get_message()
        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']
        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = "{0}/rest/handler/{1}_{2}/{3}".format(phantom_base_url, app_dir_name, app_json['appid'], asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _interactive_auth_initial(self, client_id, client_secret):

        state = self._rsh.load_app_state(self)
        self.debug_print("First time loading state: {}".format(state))

        ret_val, app_rest_url = self._get_url_to_app_rest()
        if phantom.is_fail(ret_val):
            return phantom.APP_ERROR, app_rest_url

        config = self.get_config()
        request_url = config.get("auth_url")

        # set proxy if configured
        proxy = {}
        if 'HTTP_PROXY' in os.environ:
            proxy['http'] = os.environ.get('HTTP_PROXY')
        if 'HTTPS_PROXY' in os.environ:
            proxy['https'] = os.environ.get('HTTPS_PROXY')
        state['proxy'] = proxy

        state['client_id'] = client_id
        state['redirect_url'] = app_rest_url
        state['request_url'] = request_url
        state['token_url'] = config.get("token_url")
        state['client_secret'] = base64.b64encode(client_secret.encode()).decode()

        self._rsh.save_app_state(state, self)
        self.save_progress("Redirect URI: {}".format(app_rest_url))
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'state': self._asset_id,
            'redirect_uri': app_rest_url,
            "access_type": "offline",
            "prompt": "consent"
        }
        if config.get('scopes'):
            try:
                scopes = json.loads(config['scopes'])
            except Exception:
                return phantom.APP_ERROR, "Please provide API scope in valid json format"
            params['scope'] = scopes
        try:
            url = requests.Request('GET', request_url, params=params).prepare().url
            url = '{}&'.format(url)
        except Exception as ex:
            message = self._get_error_message_from_exception(ex)
            return phantom.APP_ERROR, message

        self.save_progress("To continue, open this link in a new tab in your browser")
        self.save_progress(url)

        for i in range(0, 60):
            time.sleep(5)
            self.save_progress("." * i)
            state = self._rsh.load_app_state(self, decrypt=False)
            oauth_token = state.get('oauth_token')
            if oauth_token:
                break
            elif state.get('error'):
                return phantom.APP_ERROR, "Error retrieving OAuth token"
        else:
            return phantom.APP_ERROR, "Timed out waiting for login"
        self._state['oauth_token'] = self._rsh.load_app_state(self).get('oauth_token')
        self._state['is_encrypted'] = False
        self.debug_print("AP's Error occurred: {}".format(self._state))
        self.save_state()
        self._state = self.load_state()
        return phantom.APP_SUCCESS, ""

    def _interactive_auth_refresh(self):

        config = self.get_config()
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")

        oauth_token = self._state.get('oauth_token', {})
        if not oauth_token.get("refresh_token"):
            return phantom.APP_ERROR, "Unable to get refresh token. Has Test Connectivity been run?"

        if client_id != self._state.get('client_id', ''):
            return phantom.APP_ERROR, "Client ID has been changed. Please run Test Connectivity again."

        refresh_token = oauth_token['refresh_token']

        request_url = config.get("token_url")
        body = {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'refresh_token': refresh_token,
            'client_secret': client_secret
        }
        try:
            r = requests.post(request_url, data=body, timeout=DEFAULT_REQUEST_TIMEOUT)
        except Exception as e:
            return phantom.APP_ERROR, "Error refreshing token: {}".format(str(e))

        try:
            response_json = r.json()
            if response_json.get("error"):
                return phantom.APP_ERROR, "Invalid refresh token. Please run the test connectivity again."
            oauth_token.update(r.json())
        except Exception:
            return phantom.APP_ERROR, "Error retrieving OAuth Token"

        self._state['oauth_token'] = oauth_token
        self._state['is_encrypted'] = False
        self.save_state()
        self._state = self.load_state()
        return phantom.APP_SUCCESS, ""

    def _set_interactive_auth(self, action_result):

        config = self.get_config()
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")

        if self.get_action_identifier() != phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            if self._state.get('oauth_token'):
                if not self._state.get('oauth_token', {}).get('access_token'):
                    # try to regenerate the token from refresh token
                    self.debug_print("Access token is not available, try to generate token from refresh token")
                    ret_val, messasge = self._interactive_auth_refresh()
                    if phantom.is_fail(ret_val):
                        return phantom.APP_ERROR, messasge
            else:
                return phantom.APP_ERROR, "Unable to get tokens. Please run Test Connectivity again."

            ret_val = self._connect_to_server(action_result)
            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, action_result.get_message()
        else:
            # Run the initial authentication flow only if current action is test connectivity
            self.debug_print("Try to generate token from authorization code")
            ret_val, message = self._interactive_auth_initial(client_id, client_secret)
            self._rsh.delete_state(self)
            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, message

            self._state['client_id'] = client_id

            ret_val = self._connect_to_server(action_result)
            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, action_result.get_message()

        return phantom.APP_SUCCESS, ""

    def load_state(self):
        self._state = super().load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        return self._rsh.decrypt_state(self._state, self)

    def save_state(self):
        super().save_state(self._rsh.encrypt_state(self._state, self))

    def initialize(self):
        self._asset_id = self.get_asset_id()
        self._rsh = RequestStateHandler(self._asset_id)
        self._state = self.load_state()

        config = self.get_config()

        if config.get("auth_type", "Basic") == "Basic":
            required_params = ["username", "password"]
            for key in required_params:
                if not config.get(key):
                    return self.set_status(phantom.APP_ERROR, IMAP_REQUIRED_PARAM_BASIC.format(key))

        elif config.get("auth_type", "Basic") == "OAuth":
            required_params = ["client_id", "client_secret", "auth_url", "token_url"]
            for key in required_params:
                if not config.get(key):
                    return self.set_status(phantom.APP_ERROR, IMAP_REQUIRED_PARAM_OAUTH.format(key))

        else:
            return self.set_status(phantom.APP_ERROR, "Please provide a valid authentication mechanism to use")

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state()
        return phantom.APP_SUCCESS

    def _generate_oauth_string(self, username, access_token):
        """Generates an IMAP OAuth2 authentication string.

        See https://developers.google.com/google-apps/gmail/oauth2_overview

        Args:
            username: the username (email address) of the account to authenticate
            access_token: An OAuth2 access token.
            base64_encode: Whether to base64-encode the output.

        Returns:
            The SASL argument for the OAuth2 mechanism.
        """
        auth_string = 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)
        return auth_string

    def _connect_to_server_helper(self, action_result):
        """Redirect the flow based on auth type"""

        config = self.get_config()
        if config.get("auth_type", "Basic") == "Basic":
            return self._connect_to_server(action_result)
        else:
            ret_val, message = self._set_interactive_auth(action_result)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, message)
            return phantom.APP_SUCCESS

    def _connect_to_server(self, action_result, first_try=True):

        config = self.get_config()
        is_oauth = config.get("auth_type", "Basic") == "OAuth"

        use_ssl = config[IMAP_JSON_USE_SSL]
        server = config[phantom.APP_JSON_SERVER]

        # Set timeout to avoid stall
        socket.setdefaulttimeout(60)

        # Connect to the server
        try:
            if is_oauth or use_ssl:
                self._imap_conn = imaplib.IMAP4_SSL(server)
            else:
                self._imap_conn = imaplib.IMAP4(server)
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, IMAP_GENERAL_ERROR_MESSAGE.format(
                IMAP_ERROR_CONNECTING_TO_SERVER, error_text))

        self.save_progress(IMAP_CONNECTED_TO_SERVER)

        # Login
        try:
            if is_oauth:
                auth_string = self._generate_oauth_string(config[phantom.APP_JSON_USERNAME], self._state['oauth_token']['access_token'])
                result, data = self._imap_conn.authenticate('XOAUTH2', lambda _: auth_string)
            else:
                result, data = self._imap_conn.login(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            # If token is expired, use the refresh token to re-new the access token
            if first_try and is_oauth and "Invalid credentials" in error_text:
                self.debug_print("Try to generate token from refresh token")
                ret_val, message = self._interactive_auth_refresh()
                if phantom.is_fail(ret_val):
                    return action_result.set_status(phantom.APP_ERROR, message)
                return self._connect_to_server(action_result, False)
            return action_result.set_status(phantom.APP_ERROR, IMAP_GENERAL_ERROR_MESSAGE.format(
                IMAP_ERROR_LOGGING_IN_TO_SERVER, error_text))

        if result != 'OK':
            self.debug_print("Logging in error, result: {0} data: {1}".format(result, data))
            return action_result.set_status(phantom.APP_ERROR, IMAP_ERROR_LOGGING_IN_TO_SERVER)

        self.save_progress(IMAP_LOGGED_IN)

        # List imap data
        try:
            result, data = self._imap_conn.list()
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR,
                                            IMAP_GENERAL_ERROR_MESSAGE.format(IMAP_ERROR_LISTING_FOLDERS, error_text))

        self.save_progress(IMAP_GOT_LIST_FOLDERS)

        self._folder_name = config.get(IMAP_JSON_FOLDER, 'inbox')
        try:
            result, data = self._imap_conn.select('"{}"'.format(imap_utf7.encode(self._folder_name).decode()), True)
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, IMAP_GENERAL_ERROR_MESSAGE.format(
                IMAP_ERROR_SELECTING_FOLDER.format(folder=self._folder_name), error_text))

        if result != 'OK':
            self.debug_print("Error selecting folder, result: {0} data: {1}".format(result, data))
            return action_result.set_status(phantom.APP_ERROR, IMAP_ERROR_SELECTING_FOLDER.format(
                folder=self._folder_name))

        self.save_progress(IMAP_SELECTED_FOLDER.format(folder=self._folder_name))

        no_of_emails = data[0]
        self.debug_print("Total emails: {0}".format(no_of_emails))

        return phantom.APP_SUCCESS

    def _get_fips_enabled(self):
        try:
            from phantom_common.install_info import is_fips_enabled
        except ImportError:
            return False

        fips_enabled = is_fips_enabled()
        if fips_enabled:
            self.debug_print('FIPS is enabled')
        else:
            self.debug_print('FIPS is not enabled')
        return fips_enabled

    def _parse_email(self, muuid, rfc822_email, date_time_info=None, config=None):

        epoch = int(time.mktime(datetime.utcnow().timetuple())) * 1000

        if date_time_info:

            parse_data = parse('{left_ingore}"{dt:tg}"{right_ignore}', date_time_info)

            if not parse_data:
                # print the data
                self.debug_print("parse failed on: {0}".format(date_time_info))
                epoch = int(time.mktime(datetime.utcnow().timetuple())) * 1000
            else:
                dt = parse_data['dt']
                if not dt:
                    self.debug_print("Unable to parse dt")
                    return phantom.APP_ERROR

                dt.replace(tzinfo=tz.tzlocal())
                epoch = int(time.mktime(dt.timetuple())) * 1000
                self.debug_print("Internal date Epoch: {0}({1})".format(dt, epoch))

        if config is None:
            config = self.get_config()

        process_email = ProcessEmail()
        return process_email.process_email(self, rfc822_email, muuid, config, epoch)

    def _get_email_data_from_container(self, container_id, action_result):

        email_data = None
        email_id = None
        folder_name = None
        resp_data = {}

        ret_val, resp_data, status_code = self.get_container_info(container_id)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, str(resp_data)), email_data, email_id, folder_name

        # Keep pylint happy
        resp_data = dict(resp_data)

        email_data = resp_data.get('data', {}).get('raw_email')
        email_id = resp_data['source_data_identifier'].split()
        folder_name = email_id[0]
        email_id = email_id[-1]

        if not email_data:
            return action_result.set_status(
                phantom.APP_ERROR, "Container does not seem to be created from an IMAP email, raw_email data not found."), None, None, None

        try:
            email_id = int(email_id)
        except Exception:
            return action_result.set_status(
                phantom.APP_ERROR, "Container does not seem to be created from an IMAP email, email id not in proper format."), None, None, None

        return phantom.APP_SUCCESS, email_data, email_id, folder_name

    def _get_email_data(self, action_result, muuid, folder=None, is_diff=False):

        email_data = None
        data_time_info = None

        if is_diff:
            try:
                result, data = self._imap_conn.select('"{}"'.format(imap_utf7.encode(folder).decode()), True)
            except Exception as e:
                error_text = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, IMAP_GENERAL_ERROR_MESSAGE.format(
                    IMAP_ERROR_SELECTING_FOLDER.format(folder=folder),
                    error_text)), email_data, data_time_info

            if result != 'OK':
                self.debug_print("Error selecting folder, result: {0} data: {1}".format(result, data))
                return (action_result.set_status(phantom.APP_ERROR, IMAP_ERROR_SELECTING_FOLDER.format(
                    folder=folder)), email_data, data_time_info)

            self.save_progress(IMAP_SELECTED_FOLDER.format(folder=folder))

        # query for the whole email body
        try:
            (result, data) = self._imap_conn.uid('fetch', muuid, "(INTERNALDATE RFC822)")
        except TypeError:  # py3
            (result, data) = self._imap_conn.uid('fetch', str(muuid), "(INTERNALDATE RFC822)")
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, IMAP_FETCH_ID_FAILED.format(
                muuid=muuid, excep=error_text)), email_data, data_time_info

        if result != 'OK':
            self.save_progress(IMAP_FETCH_ID_FAILED_RESULT, muuid=muuid, result=result, data=data)
            return action_result.set_status(
                phantom.APP_ERROR, IMAP_FETCH_ID_FAILED_RESULT.format(muuid=muuid, result=result, data=data)), email_data, data_time_info

        if not data:
            error_message = "Data returned empty for {muuid} with result: {result} and data: {data}. Email ID possibly not present.".format(
                muuid=muuid, result=result, data=data)
            return action_result.set_status(phantom.APP_ERROR, error_message), email_data, data_time_info

        if not isinstance(data, list):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Data returned is not a list for {muuid} with result: {result} and data: {data}".format(muuid=muuid, result=result, data=data)
            ), email_data, data_time_info

        if not data[0]:
            error_message = "Data[0] returned empty for {muuid} with result: {result} and data: {data}. Email ID possibly not present.".format(
                muuid=muuid, result=result, data=data)
            return action_result.set_status(phantom.APP_ERROR, error_message), email_data, data_time_info

        if not isinstance(data[0], tuple):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Data[0] returned is not a list for {muuid} with result: {result} and data: {data}".format(muuid=muuid, result=result, data=data)
            ), email_data, data_time_info

        if len(data[0]) < 2:
            error_message = "Data[0] does not contain all parts for {muuid} with result: {result} and data: {data}".format(
                muuid=muuid, result=result, data=data)
            return action_result.set_status(phantom.APP_ERROR, error_message), email_data, data_time_info

        # parse the email body into an object, we've ALREADY VALIDATED THAT DATA[0] CONTAINS >= 2 ITEMS
        email_data = data[0][1].decode('UTF-8')
        data_time_info = data[0][0].decode('UTF-8')

        return phantom.APP_SUCCESS, email_data, data_time_info

    def _handle_email(self, muuid, param):

        action_result = ActionResult(dict(param))

        ret_val, email_data, data_time_info = self._get_email_data(action_result, muuid, folder=None, is_diff=False)

        if phantom.is_fail(ret_val):
            self.debug_print("Error in getting Email Data with id: {0}. Reason: {1}".format(muuid, action_result.get_message()))
            return action_result.get_status()

        return self._parse_email(muuid, email_data, data_time_info)

    def _get_email_ids_to_process(self, max_emails, lower_id, manner):

        try:
            # Method to fetch all UIDs
            result, data = self._imap_conn.uid('search', None, "UID {}:*".format(str(lower_id)))
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            message = "Failed to get latest email ids. Message: {0}".format(error_text)
            return phantom.APP_ERROR, message, None

        if result != 'OK':
            message = "Failed to get latest email ids. Server response: {0}".format(data)
            return phantom.APP_ERROR, message, None

        if not data:
            return phantom.APP_SUCCESS, "Empty data", None

        # get the UIDs
        uids = [int(uid) for uid in data[0].split()]
        if not uids:
            return phantom.APP_SUCCESS, "Empty UID list", None

        # if nothing came on or after the lower_id then return
        if not uids:
            return phantom.APP_SUCCESS, "Empty UID list when greater than lower_id: {0}".format(lower_id), None

        # sort it
        uids.sort()

        # see how many we are supposed to return
        max_emails = int(max_emails)

        if manner == IMAP_INGEST_LATEST_EMAILS:
            self.save_progress("Getting {0} MOST RECENT emails uids since uid(inclusive) {1}".format(max_emails, lower_id))
            # return the latest i.e. the rightmost items in the list
            return phantom.APP_SUCCESS, "", uids[-max_emails:]

        # return the oldest i.e. the leftmost items in the list
        self.save_progress("Getting NEXT {0} email uids since uid(inclusive) {1}".format(max_emails, lower_id))
        return phantom.APP_SUCCESS, "", uids[:max_emails]

    def _get_mail_header_dict(self, mail):

        headers = mail.__dict__.get('_headers')

        if not headers:
            return {}

        ret_val = {}
        for header in headers:
            try:
                ret_val[header[0]] = str(make_header(decode_header(header[1])))
            except Exception:
                process_email = ProcessEmail()
                ret_val[header[0]] = process_email._decode_uni_string(header[1], header[1])

        return ret_val

    def _get_container_id(self, email_id, folder, verify=False):

        url = '{0}/rest/container?_filter_source_data_identifier="{1} : {2}"&_filter_asset={3}'.format(
                self._get_phantom_base_url().strip('/'), folder, email_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            resp_json = r.json()
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            self.debug_print("Unable to query Email container. {}".format(error_text))
            return None

        if resp_json.get('count', 0) <= 0:
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            self.debug_print("Container results, not proper", error_text)
            return None

        return container_id

    def _get_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        email_id = param.get(IMAP_JSON_ID)
        container_id = None
        if param.get(IMAP_JSON_CONTAINER_ID) is not None:
            container_id = self.validate_integers(action_result, param.get(IMAP_JSON_CONTAINER_ID), IMAP_JSON_CONTAINER_ID)
            if container_id is None:
                return action_result.get_status()
        email_data = None
        data_time_info = None

        if not email_id and not container_id:
            return action_result.set_status(phantom.APP_ERROR, "Please specify either id or container_id to get the email")

        if container_id:
            ret_val, email_data, email_id, folder = self._get_email_data_from_container(container_id, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            self._is_hex = True
            self._folder_name = folder
        elif email_id:
            if phantom.is_fail(self._connect_to_server_helper(action_result)):
                return action_result.get_status()

            is_diff = False
            folder = param.get(IMAP_JSON_FOLDER, self._folder_name)
            if folder != self._folder_name:
                is_diff = True
                self._folder_name = folder

            ret_val, email_data, data_time_info = self._get_email_data(action_result, email_id, folder, is_diff)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            fips_enabled = self._get_fips_enabled()
            # if fips is not enabled, we should continue with our existing md5 usage for generating hashes
            # to not impact existing customers
            if not fips_enabled:
                folder = hashlib.md5(folder.encode())
            else:
                folder = hashlib.sha256(folder.encode())
            folder = folder.hexdigest()

        mail = email.message_from_string(email_data)

        mail_header_dict = self._get_mail_header_dict(mail)

        action_result.add_data(mail_header_dict)

        ingest_email = param.get(IMAP_JSON_INGEST_EMAIL, False)

        if not ingest_email:
            return action_result.set_status(phantom.APP_SUCCESS, "Email not ingested.")

        # Create a config dictionary to represent everything is to be extracted.
        config = {
            "extract_attachments": True,
            "extract_domains": True,
            "extract_hashes": True,
            "extract_ips": True,
            "extract_urls": True
        }

        header_date = mail_header_dict.get('Date')
        if (data_time_info is None) and (header_date is not None):
            data_time_info = 'ignore_left "{0}" ignore_right'.format(header_date)

        ret_val, message = self._parse_email(email_id, email_data, data_time_info, config=config)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, message)

        # get the container id that of the email that was ingested
        container_id = self._get_container_id(email_id, folder)

        action_result.update_summary({"container_id": container_id})

        action_result.set_status(phantom.APP_SUCCESS)

    def _poll_now(self, action_result, param):

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        # Get the maximum number of emails that we can pull, same as container count
        max_emails = self.validate_integers(
            action_result, param.get(phantom.APP_JSON_CONTAINER_COUNT, IMAP_DEFAULT_CONTAINER_COUNT), "container_count")
        if not max_emails:
            return action_result.get_status()

        self.save_progress("POLL NOW Getting {0} most recent email uid(s)".format(max_emails))
        ret_val, ret_msg, email_ids = self._get_email_ids_to_process(max_emails, 1, config[IMAP_JSON_INGEST_MANNER])

        if phantom.is_fail(ret_val):
            return action_result.set_status(ret_val, ret_msg)

        if not email_ids:
            return action_result.set_status(phantom.APP_SUCCESS)

        if len(email_ids) != max_emails:
            self.save_progress("Got {0} recent emails".format(len(email_ids)))

        for i, email_id in enumerate(email_ids):
            self.send_progress("Parsing email uid: {0}".format(email_id))
            try:
                self._handle_email(email_id, param)
            except Exception as e:
                error_text = self._get_error_message_from_exception(e)
                self.debug_print("ErrorExp in _handle_email # {0} {1}".format(i, error_text))
                # continue to process the next email

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connect to the server
        if phantom.is_fail(self._connect_to_server_helper(action_result)):
            return action_result.get_status()

        if self.is_poll_now():
            return self._poll_now(action_result, param)

        lower_id = self._state.get('next_muid', 1)

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        # default the max emails to the normal on_poll max emails
        max_emails = config[IMAP_JSON_MAX_EMAILS]

        # Get the email ids that we will be querying for, different set for first run
        if self._state.get('first_run', True):
            # set the config to _not_ first run
            self._state['first_run'] = False
            max_emails = config[IMAP_JSON_FIRST_RUN_MAX_EMAILS]
            self.save_progress("First time Ingestion detected.")

        ret_val, ret_msg, email_ids = self._get_email_ids_to_process(max_emails, lower_id, config[IMAP_JSON_INGEST_MANNER])

        if phantom.is_fail(ret_val):
            return action_result.set_status(ret_val, ret_msg)

        if not email_ids:
            return action_result.set_status(phantom.APP_SUCCESS)

        for i, email_id in enumerate(email_ids):
            self.send_progress("Parsing email uid: {0}".format(email_id))
            try:
                self._handle_email(email_id, param)
            except Exception as e:
                error_text = self._get_error_message_from_exception(e)
                self.debug_print("ErrorExp in _handle_email # {0}".format(i), error_text)
                return action_result.set_status(phantom.APP_ERROR)

        if email_ids:
            self._state['next_muid'] = int(email_ids[-1]) + 1

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connect to the server
        if phantom.is_fail(self._connect_to_server_helper(action_result)):
            self.save_progress(IMAP_ERROR_CONNECTIVITY_TEST)
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(IMAP_SUCCESS_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS, IMAP_SUCCESS_CONNECTIVITY_TEST)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if action == phantom.ACTION_ID_INGEST_ON_POLL:
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress("Time taken: {0}".format(human_time))
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif action == self.ACTION_ID_GET_EMAIL:
            result = self._get_email(param)

        return result


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()
    in_json = None
    in_email = None

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None
    verify = args.verify

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = "{}login".format(BaseConnector._get_phantom_base_url())
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:

        in_json = f.read()
        in_json = json.loads(in_json)

        connector = ImapConnector()
        connector.print_progress_message = True

        data = in_json.get('data')
        raw_email = in_json.get('raw_email')

        # if neither present then treat it as a normal action test json
        if not data and not raw_email:
            print(json.dumps(in_json, indent=4))

            if session_id is not None:
                in_json['user_session_token'] = session_id
            result = connector._handle_action(json.dumps(in_json), None)
            print(result)
            sys.exit(0)

        if data:
            raw_email = data.get('raw_email')

        if raw_email:
            config = {
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True,
                "add_body_to_header_artifacts": True
            }

            process_email = ProcessEmail()
            ret_val, message = process_email.process_email(connector, raw_email, "manual_parsing", config, None)

    sys.exit(0)
