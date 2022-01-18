# File: imap_connector.py
#
# Copyright (c) 2014-2021 Splunk Inc.
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
import codecs
import email
import hashlib
import imaplib
import json
import socket
import sys
import time
from builtins import str
from datetime import datetime, timedelta
from email.header import decode_header, make_header

import phantom.app as phantom
import requests
from bs4 import UnicodeDammit
from dateutil import tz
from parse import parse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from imap_consts import *
from process_email import ProcessEmail


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

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = IMAP_ERROR_CODE_MESSAGE
                    error_msg = e.args[0]
            else:
                error_code = IMAP_ERROR_CODE_MESSAGE
                error_msg = IMAP_ERROR_MESSAGE
        except:
            error_code = IMAP_ERROR_CODE_MESSAGE
            error_msg = IMAP_ERROR_MESSAGE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERROR_MESSAGE
        except:
            error_msg = IMAP_ERROR_MESSAGE

        return error_code, error_msg

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """
        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, IMAP_VALIDATE_INTEGER_MESSAGE.format(key=key))
                return None
            parameter = int(parameter)

        except:
            action_result.set_status(phantom.APP_ERROR, IMAP_VALIDATE_INTEGER_MESSAGE.format(key=key))
            return None

        if parameter < 0:
            action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {} parameter".format(key))
            return None
        if not allow_zero and parameter == 0:
            action_result.set_status(phantom.APP_ERROR, "Please provide a positive integer value in the {} parameter".format(key))
            return None

        return parameter

    def initialize(self):

        self._state = self.load_state()
        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while fetching the Phantom server's Python major version")

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _connect_to_server(self, action_result, param):

        config = self.get_config()

        use_ssl = config[IMAP_JSON_USE_SSL]
        server = config[phantom.APP_JSON_SERVER]

        # Set timeout to avoid stall
        socket.setdefaulttimeout(60)

        # Connect to the server
        try:
            if use_ssl:
                self._imap_conn = imaplib.IMAP4_SSL(server)
            else:
                self._imap_conn = imaplib.IMAP4(server)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "{}. Details: {}".format(IMAP_ERR_CONNECTING_TO_SERVER, error_text))

        self.save_progress(IMAP_CONNECTED_TO_SERVER)

        # Login
        try:
            (result, data) = self._imap_conn.login(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "{}. Details: {}".format(IMAP_ERR_LOGGING_IN_TO_SERVER, error_text))

        if result != 'OK':
            self.debug_print("Logging in error, result: {0} data: {1}".format(result, data))
            return action_result.set_status(phantom.APP_ERROR, IMAP_ERR_LOGGING_IN_TO_SERVER)

        self.save_progress(IMAP_LOGGED_IN)

        # List imap data
        try:
            (result, data) = self._imap_conn.list()
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "{}. Details: {}".format(IMAP_ERR_LISTING_FOLDERS, error_text))

        self.save_progress(IMAP_GOT_LIST_FOLDERS)

        self._folder_name = config.get(IMAP_JSON_FOLDER, 'inbox')
        try:
            (result, data) = self._imap_conn.select('"{}"'.format(codecs.encode(self._folder_name, "utf-7").replace(b"&", b"&-")
                .replace(b"'", b"\'").replace(b"+-", b"+")
                .replace(b"+AH4", b"~").replace(b"+AFw", b"\\\\").decode()), True)
            if result != 'OK':
                (result, data) = self._imap_conn.select('"{}"'.format(
                    codecs.encode(self._folder_name, "utf-7").replace(b"+", b"&").decode()), True)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "{}. Details: {}".format(IMAP_ERR_SELECTING_FOLDER.format(
                    folder=self._handle_py_ver_compat_for_input_str(self._folder_name)), error_text))

        if result != 'OK':
            self.debug_print("Error selecting folder, result: {0} data: {1}".format(result, data))
            return action_result.set_status(phantom.APP_ERROR, IMAP_ERR_SELECTING_FOLDER.format(
                folder=self._handle_py_ver_compat_for_input_str(self._folder_name)))

        self.save_progress(IMAP_SELECTED_FOLDER.format(folder=self._handle_py_ver_compat_for_input_str(self._folder_name)))

        no_of_emails = data[0]
        self.debug_print("Total emails: {0}".format(no_of_emails))

        return phantom.APP_SUCCESS

    def _get_fips_enabled(self):
        try:
            from phantom_common.install_info import is_fips_enabled
        except ImportError:
            return False

        fips_enabled = is_fips_enabled()
        if (fips_enabled):
            self.debug_print('fips is enabled')
        else:
            self.debug_print('fips is not enabled')
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

        if (phantom.is_fail(ret_val)):
            return (action_result.set_status(phantom.APP_ERROR, str(resp_data)), email_data, email_id, folder_name)

        # Keep pylint happy
        resp_data = dict(resp_data)

        email_data = resp_data.get('data', {}).get('raw_email')
        email_id = resp_data['source_data_identifier'].split()
        folder_name = email_id[0]
        email_id = email_id[-1]

        if not email_data:
            return (action_result.set_status(phantom.APP_ERROR, "Container does not seem to be created from an IMAP email, \
                raw_email data not found."), None, None, None)

        try:
            email_id = int(email_id)
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Container does not seem to be created from an IMAP email, \
                email id not in proper format."), None, None, None)

        return (phantom.APP_SUCCESS, email_data, email_id, folder_name)

    def _get_email_data(self, action_result, muuid, folder=None, is_diff=False):

        email_data = None
        data_time_info = None

        if is_diff:
            try:
                (result, data) = self._imap_conn.select('"{}"'.format(
                    codecs.encode(folder, "utf-7").replace(b"&", b"&-").replace(b"'", b"\'").replace(
                        b"+-", b"+").replace(b"+AH4", b"~").replace(b"+AFw", b"\\\\").decode()), True)
                if result != 'OK':
                    (result, data) = self._imap_conn.select('"{}"'.format(
                        codecs.encode(folder, "utf-7").replace(b"+", b"&").decode()), True)
            except Exception as e:
                return (action_result.set_status(phantom.APP_ERROR, "{}. Details: {}".format(IMAP_ERR_SELECTING_FOLDER.format(
                        folder=self._handle_py_ver_compat_for_input_str(folder)), self._get_error_message_from_exception(e))),
                            email_data, data_time_info)

            if result != 'OK':
                self.debug_print("Error selecting folder, result: {0} data: {1}".format(result, data))
                return (action_result.set_status(phantom.APP_ERROR, IMAP_ERR_SELECTING_FOLDER.format(
                    folder=self._handle_py_ver_compat_for_input_str(folder))), email_data, data_time_info)

            self.save_progress(IMAP_SELECTED_FOLDER.format(folder=self._handle_py_ver_compat_for_input_str(folder)))

        # query for the whole email body
        try:
            (result, data) = self._imap_conn.uid('fetch', muuid, "(INTERNALDATE RFC822)")
        except TypeError:  # py3
            (result, data) = self._imap_conn.uid('fetch', str(muuid), "(INTERNALDATE RFC822)")
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            return (action_result.set_status(phantom.APP_ERROR, IMAP_FETCH_ID_FAILED.format(muuid=muuid,
                excep=error_text)), email_data, data_time_info)

        if result != 'OK':
            self.save_progress(IMAP_FETCH_ID_FAILED_RESULT, muuid=muuid, result=result, data=data)
            return (action_result.set_status(phantom.APP_ERROR,
                IMAP_FETCH_ID_FAILED_RESULT.format(muuid=muuid, result=result, data=data)), email_data, data_time_info)

        if not data:
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data returned empty for {muuid} with result: {result} and data: {data}. Email ID possibly not present."
                            .format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        if (type(data) != list):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data returned is not a list for {muuid} with result: {result} and data: {data}".format(muuid=muuid,
                            result=result, data=data)),
                    email_data, data_time_info)

        if not data[0]:
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data[0] returned empty for {muuid} with result: {result} and data: {data}. Email ID possibly not \
                            present.".format(muuid=muuid, result=result, data=data)), email_data, data_time_info)

        if (type(data[0]) != tuple):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data[0] returned is not a list for {muuid} with result: {result} and data: \
                            {data}".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        if (len(data[0]) < 2):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data[0] does not contain all parts for {muuid} with result: {result} and data: \
                            {data}".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        # parse the email body into an object, we've ALREADY VALIDATED THAT DATA[0] CONTAINS >= 2 ITEMS
        email_data = data[0][1].decode('UTF-8')
        data_time_info = data[0][0].decode('UTF-8')

        return (phantom.APP_SUCCESS, email_data, data_time_info)

    def _handle_email(self, muuid, param):

        action_result = ActionResult(dict(param))

        ret_val, email_data, data_time_info = self._get_email_data(action_result, muuid, folder=None, is_diff=False)

        if (phantom.is_fail(ret_val)):
            self.debug_print("Error in getting Email Data with id: {0}. Reason: {1}".format(muuid, action_result.get_message()))
            return action_result.get_status()

        return self._parse_email(muuid, email_data, data_time_info)

    def _get_email_ids_to_process(self, max_emails, lower_id, manner):

        range = "1:*"

        try:
            (result, data) = self._imap_conn.uid('fetch', range, "(UID)")
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            message = "Failed to get latest email ids. Message: {0}".format(error_text)
            return (phantom.APP_ERROR, message, None)

        if result != 'OK':
            message = "Failed to get latest email ids. Server response: {0}".format(data)
            return (phantom.APP_ERROR, message, None)

        if not data:
            return (phantom.APP_SUCCESS, "Empty data", None)

        # get the UIDs
        uids = []
        for line in data:
            if not line:
                continue
            try:
                parse_data = parse('{left_ingore}(UID {uid})', line)
            except TypeError:  # py3
                parse_data = parse('{left_ingore}(UID {uid})', line.decode('UTF-8'))

            if not parse_data:
                continue

            uid = parse_data['uid']
            if not uid:
                continue

            uids.append(int(uid))

        if not uids:
            return (phantom.APP_SUCCESS, "Empty UID list", None)

        # get the emails that came in on or after lower_id
        lower_id = int(lower_id)
        greater_than_lower_id = [x for x in uids if x >= lower_id]
        uids = greater_than_lower_id

        # if nothing came on or after the lower_id then return
        if not uids:
            return (phantom.APP_SUCCESS, "Empty UID list when greater than lower_id: {0}".format(lower_id), None)

        # sort it
        uids.sort()

        # see how many we are supposed to return
        max_emails = int(max_emails)

        if (manner == IMAP_INGEST_LATEST_EMAILS):
            self.save_progress("Getting {0} MOST RECENT emails uids since uid(inclusive) {1}".format(max_emails, lower_id))
            # return the latest i.e the the rightmost items in the list
            return (phantom.APP_SUCCESS, "", uids[-max_emails:])

        # return the oldest i.e the the leftmost items in the list
        self.save_progress("Getting NEXT {0} email uids since uid(inclusive) {1}".format(max_emails, lower_id))
        return (phantom.APP_SUCCESS, "", uids[:max_emails])

    def _get_mail_header_dict(self, mail):

        headers = mail.__dict__.get('_headers')

        if not headers:
            return {}

        ret_val = {}
        for header in headers:
            try:
                ret_val[header[0]] = str(make_header(decode_header(header[1])))
            except:
                process_email = ProcessEmail()
                ret_val[header[0]] = process_email._decode_uni_string(header[1], header[1])

        return ret_val

    def _get_container_id(self, email_id, folder):

        url = '{0}/rest/container?_filter_source_data_identifier="{1} : {2}"&_filter_asset={3}'.format(
                self._get_phantom_base_url().strip('/'), folder, email_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Unable to query Email container. {}".format(error_text))
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
            self.debug_print("Container results, not proper", error_text)
            return None

        return container_id

    def _get_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        email_id = self._handle_py_ver_compat_for_input_str(param.get(IMAP_JSON_ID))
        container_id = None
        if param.get(IMAP_JSON_CONTAINER_ID) is not None:
            container_id = self._validate_integers(action_result, param.get(IMAP_JSON_CONTAINER_ID), IMAP_JSON_CONTAINER_ID)
            if container_id is None:
                return action_result.get_status()
        email_data = None
        data_time_info = None

        if (not email_id and not container_id):
            return action_result.set_status(phantom.APP_ERROR, "Please specify either id or container_id to get the email")

        if container_id:
            ret_val, email_data, email_id, folder = self._get_email_data_from_container(container_id, action_result)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
            self._is_hex = True
            self._folder_name = folder
        elif email_id:
            if (phantom.is_fail(self._connect_to_server(action_result, param))):
                return action_result.get_status()

            is_diff = False
            folder = self._handle_py_ver_compat_for_input_str(param.get(IMAP_JSON_FOLDER, ""))
            if folder and folder != self._folder_name:
                is_diff = True
                self._folder_name = folder
            if not folder and self._folder_name:
                folder = self._folder_name

            ret_val, email_data, data_time_info = self._get_email_data(action_result, email_id, folder, is_diff)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

        fips_enabled = self._get_fips_enabled()
        # if fips is not enabled, we should continue with our existing md5 usage for generating hashes
        # to not impact existing customers
        try:
            if (not fips_enabled):
                folder = hashlib.md5(folder)
            else:
                folder = hashlib.sha256(folder)
        except:
            if (not fips_enabled):
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
                "extract_urls": True }

        header_date = mail_header_dict.get('Date')
        if (data_time_info is None) and (header_date is not None):
            data_time_info = 'ignore_left "{0}" ignore_right'.format(header_date)

        ret_val, message = self._parse_email(email_id, email_data, data_time_info, config=config)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, message)

        # get the container id that of the email that was ingested
        container_id = self._get_container_id(email_id, folder)

        action_result.update_summary({"container_id": container_id})

        action_result.set_status(phantom.APP_SUCCESS)

    def _poll_now(self, action_result, param):

        # Connect to the server
        if (phantom.is_fail(self._connect_to_server(action_result, param))):
            return action_result.get_status()

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        # Get the maximum number of emails that we can pull, same as container count
        max_emails = self._validate_integers(action_result, param.get(phantom.APP_JSON_CONTAINER_COUNT,
            IMAP_DEFAULT_CONTAINER_COUNT), "container_count")
        if max_emails is None:
            return action_result.get_status()

        self.save_progress("POLL NOW Getting {0} most recent email uid(s)".format(max_emails))
        ret_val, ret_msg, email_ids = self._get_email_ids_to_process(max_emails, 1, config[IMAP_JSON_INGEST_MANNER])

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(ret_val, ret_msg)

        if not email_ids:
            return action_result.set_status(phantom.APP_SUCCESS)

        if (len(email_ids) != max_emails):
            self.save_progress("Got {0} recent emails".format(len(email_ids)))

        for i, email_id in enumerate(email_ids):
            self.send_progress("Parsing email uid: {0}".format(email_id))
            try:
                self._handle_email(email_id, param)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
                self.debug_print("ErrorExp in _handle_email # {0} {1}".format(i, error_text))
                # continue to process the next email

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if (param.get(phantom.APP_JSON_CONTAINER_COUNT) != MAX_COUNT_VALUE):
            return self._poll_now(action_result, param)

        # Connect to the server
        if (phantom.is_fail(self._connect_to_server(action_result, param))):
            return action_result.get_status()

        lower_id = self._state.get('next_muid', '1')

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        # default the max emails to the normal on_poll max emails
        max_emails = config[IMAP_JSON_MAX_EMAILS]

        # Get the email ids that we will be querying for, different set for first run
        if (self._state.get('first_run', True)):
            # set the config to _not_ first run
            self._state['first_run'] = False
            max_emails = config[IMAP_JSON_FIRST_RUN_MAX_EMAILS]
            self.save_progress("First time Ingestion detected.")

        ret_val, ret_msg, email_ids = self._get_email_ids_to_process(max_emails, lower_id, config[IMAP_JSON_INGEST_MANNER])

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(ret_val, ret_msg)

        if not email_ids:
            return action_result.set_status(phantom.APP_SUCCESS)

        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, IMAP_DEFAULT_CONTAINER_COUNT))

        if (container_count < len(email_ids)):
            self.save_progress("Trimming emails to process to {0}".format(container_count))
            email_ids = email_ids[-container_count:]

        for i, email_id in enumerate(email_ids):
            self.send_progress("Parsing email uid: {0}".format(email_id))
            try:
                self._handle_email(email_id, param)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = IMAP_EXCEPTION_ERR_MESSAGE.format(error_code, error_msg)
                self.debug_print("ErrorExp in _handle_email # {0}".format(i), error_text)
                return action_result.set_status(phantom.APP_ERROR)

        if email_ids:
            self._state['next_muid'] = int(email_ids[-1]) + 1

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connect to the server
        if (phantom.is_fail(self._connect_to_server(action_result, param))):
            action_result.append_to_message(self._handle_py_ver_compat_for_input_str(IMAP_ERR_CONNECTIVITY_TEST))
            return action_result.get_status()

        self.save_progress(IMAP_SUCC_CONNECTIVITY_TEST)

        return action_result.set_status(phantom.APP_SUCCESS, IMAP_SUCC_CONNECTIVITY_TEST)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if (action == phantom.ACTION_ID_INGEST_ON_POLL):
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress("Time taken: {0}".format(human_time))
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity(param)
        elif (action == self.ACTION_ID_GET_EMAIL):
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

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:

        in_json = f.read()
        in_json = json.loads(in_json)

        connector = ImapConnector()
        connector.print_progress_message = True

        data = in_json.get('data')
        raw_email = in_json.get('raw_email')

        # if neither present then treat it as a normal action test json
        if (not data and not raw_email):
            print(json.dumps(in_json, indent=4))

            if (session_id is not None):
                in_json['user_session_token'] = session_id
            result = connector._handle_action(json.dumps(in_json), None)
            print(result)
            exit(0)

        if (data):
            raw_email = data.get('raw_email')

        if (raw_email):
            config = {
                    "extract_attachments": True,
                    "extract_domains": True,
                    "extract_hashes": True,
                    "extract_ips": True,
                    "extract_urls": True,
                    "add_body_to_header_artifacts": True }

            process_email = ProcessEmail()
            ret_val, message = process_email.process_email(connector, raw_email, "manual_parsing", config, None)

    exit(0)
