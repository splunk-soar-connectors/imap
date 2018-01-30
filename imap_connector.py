# --
# File: imap_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom

# THIS Connector imports
from imap_consts import *

import imaplib
from datetime import datetime
from datetime import timedelta
import time
from parse import parse
from dateutil import tz
import json
from process_email import ProcessEmail
import email
import requests

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


class ImapConnector(BaseConnector):

    ACTION_ID_GET_EMAIL = "get_email"

    def __init__(self):

        # Call the EmailConnector init first
        super(ImapConnector, self).__init__()

        self._imap_conn = None
        self._state_file_path = None
        self._state = {}

    def initialize(self):

        self._state = self.load_state()

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _connect_to_server(self, param):

        config = self.get_config()

        use_ssl = config[IMAP_JSON_USE_SSL]
        server = config[phantom.APP_JSON_SERVER]

        # Connect to the server
        try:
            if (use_ssl):
                self._imap_conn = imaplib.IMAP4_SSL(server)
            else:
                self._imap_conn = imaplib.IMAP4(server)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, IMAP_ERR_CONNECTING_TO_SERVER, e)

        self.save_progress(IMAP_CONNECTED_TO_SERVER)

        # Login
        try:
            (result, data) = self._imap_conn.login(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, IMAP_ERR_LOGGING_IN_TO_SERVER, e)

        if (result != 'OK'):
            self.debug_print("Logging in error, result: {0} data: {1}".format(result, data))
            return self.set_status(phantom.APP_ERROR, IMAP_ERR_LOGGING_IN_TO_SERVER, e)

        self.save_progress(IMAP_LOGGED_IN)

        # List imap data
        try:
            (result, data) = self._imap_conn.list()
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, IMAP_ERR_LISTING_FOLDERS, e)

        self.save_progress(IMAP_GOT_LIST_FOLDERS)

        folder = config.get(IMAP_JSON_FOLDER, 'inbox')
        try:
            (result, data) = self._imap_conn.select(folder, True)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, IMAP_ERR_SELECTING_FOLDER.format(folder=folder), e)

        if (result != 'OK'):
            self.debug_print("Error selecting folder, result: {0} data: {1}".format(result, data))
            return self.set_status(phantom.APP_ERROR, IMAP_ERR_SELECTING_FOLDER.format(folder=folder))

        self.save_progress(IMAP_SELECTED_FOLDER.format(folder=folder))

        no_of_emails = data[0]
        self.debug_print("Total emails: {0}".format(no_of_emails))

        return phantom.APP_SUCCESS

    def _parse_email(self, muuid, rfc822_email, date_time_info=None, config=None):

        epoch = int(time.mktime(datetime.utcnow().timetuple())) * 1000

        if (date_time_info):

            parse_data = parse('{left_ingore}"{dt:tg}"{right_ignore}', date_time_info)

            if (not parse_data):
                # print the data
                self.debug_print("parse failed on: {0}".format(date_time_info))
                epoch = int(time.mktime(datetime.utcnow().timetuple())) * 1000
            else:
                dt = parse_data['dt']
                if (not dt):
                    self.debug_print("Unable to parse dt")
                    return phantom.APP_ERROR

                dt.replace(tzinfo=tz.tzlocal())
                epoch = int(time.mktime(dt.timetuple())) * 1000
                self.debug_print("Internal date Epoch: {0}({1})".format(dt, epoch))

        if (config is None):
            config = self.get_config()

        process_email = ProcessEmail()
        return process_email.process_email(self, rfc822_email, muuid, config, epoch)

    def _get_email_data_from_container(self, container_id, action_result):

        email_data = None
        email_id = None
        resp_data = {}

        ret_val, resp_data, status_code = self.get_container_info(container_id)

        if (phantom.is_fail(ret_val)):
            return (action_result.set_status(phantom.APP_ERROR, str(resp_data)), email_data, email_id)

        # Keep pylint happy
        resp_data = dict(resp_data)

        email_data = resp_data.get('data', {}).get('raw_email')
        email_id = resp_data['source_data_identifier']

        if (not email_data):
            return (action_result.set_status(phantom.APP_ERROR, "Container does not seem to be created from an IMAP email, raw_email data not found."), None, None)

        try:
            email_id = int(email_id)
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Container does not seem to be created from an IMAP email, email id not in proper format."), None, None)

        return (phantom.APP_SUCCESS, email_data, email_id)

    def _get_email_data(self, muuid, action_result):

        email_data = None
        data_time_info = None

        # query for the whole email body
        try:
            (result, data) = self._imap_conn.uid('fetch', muuid, "(INTERNALDATE RFC822)")
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, IMAP_FETCH_ID_FAILED.format(muuid=muuid, excep=str(e))), email_data, data_time_info)

        if (result != 'OK'):
            self.save_progress(IMAP_FETCH_ID_FAILED_RESULT, muuid=muuid, result=result, data=data)
            return (action_result.set_status(phantom.APP_ERROR,
                IMAP_FETCH_ID_FAILED_RESULT.format(muuid=muuid, result=result, data=data)), email_data, data_time_info)

        if (not data):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data returned empty for {muuid} with result: {result} and data: {data}. Email ID possibly not present.".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        if (type(data) != list):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data returned is not a list for {muuid} with result: {result} and data: {data}".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        if (not data[0]):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data[0] returned empty for {muuid} with result: {result} and data: {data}. Email ID possibly not present.".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        if (type(data[0]) != tuple):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data[0] returned is not a list for {muuid} with result: {result} and data: {data}".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        if (len(data[0]) < 2):
            return (action_result.set_status(phantom.APP_ERROR,
                        "Data[0] does not contain all parts for {muuid} with result: {result} and data: {data}".format(muuid=muuid, result=result, data=data)),
                    email_data, data_time_info)

        # parse the email body into an object, we've ALREADY VALIDATED THAT DATA[0] CONTAINS >= 2 ITEMS
        email_data = data[0][1]
        data_time_info = data[0][0]

        return (phantom.APP_SUCCESS, email_data, data_time_info)

    def _handle_email(self, muuid, param):

        action_result = ActionResult(dict(param))

        ret_val, email_data, data_time_info = self._get_email_data(muuid, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print("Error in getting Email Data with id: {0}. Reason: {1}".format(muuid, action_result.get_message()))
            return action_result.get_status()

        return self._parse_email(muuid, email_data, data_time_info)

    def _get_email_ids_to_process(self, max_emails, lower_id, manner):

        range = "1:*"

        try:
            (result, data) = self._imap_conn.uid('fetch', range, "(UID)")
        except Exception as e:
            message = "Failed to get latest email ids. Message: {0}".format(e.message)
            return (phantom.APP_ERROR, message, None)

        if (result != 'OK'):
            message = "Failed to get latest email ids. Server response: {0}".format(data)
            return (phantom.APP_ERROR, message, None)

        if (not data):
            return (phantom.APP_SUCCESS, "Empty data", None)

        # get the UIDs
        uids = []
        for line in data:
            if (not line):
                continue
            parse_data = parse('{left_ingore}(UID {uid})', line)

            if (not parse_data):
                continue

            uid = parse_data['uid']
            if (not uid):
                continue

            uids.append(int(uid))

        if (not uids):
            return (phantom.APP_SUCCESS, "Empty UID list", None)

        # get the emails that came in on or after lower_id
        lower_id = int(lower_id)
        greater_than_lower_id = [x for x in uids if x >= lower_id]
        uids = greater_than_lower_id

        # if nothing came on or after the lower_id then return
        if (not uids):
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

        if (not headers):
            return {}

        ret_val = {}
        for header in headers:
            ret_val[header[0]] = header[1]

        return ret_val

    def _get_container_id(self, email_id):

        url = 'https://127.0.0.1/rest/container?_filter_source_data_identifier="{0}"&_filter_asset={1}'.format(email_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Unable to query Email container", e)
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            self.debug_print("Container results, not proper", e)
            return None

        return container_id

    def _get_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        email_id = param.get(IMAP_JSON_ID)
        container_id = param.get(IMAP_JSON_CONTAINER_ID)
        email_data = None
        data_time_info = None

        if (not email_id and not container_id):
            return action_result.set_status(phantom.APP_ERROR, "Please specify either id or container_id to get the email")

        if (container_id):
            ret_val, email_data, email_id = self._get_email_data_from_container(container_id, action_result)
        elif (email_id):
            # Connect to the server
            if (phantom.is_fail(self._connect_to_server(param))):
                return self.get_status()

            ret_val, email_data, data_time_info = self._get_email_data(email_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        mail = email.message_from_string(email_data)

        mail_header_dict = self._get_mail_header_dict(mail)

        action_result.add_data(mail_header_dict)

        ingest_email = param.get(IMAP_JSON_INGEST_EMAIL, False)

        if (not ingest_email):
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
            data_time_info = 'igonre_left "{0}" ignore_right'.format(header_date)

        ret_val, message = self._parse_email(email_id, email_data, data_time_info, config=config)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, message)

        # get the container id that of the email that was ingested
        container_id = self._get_container_id(email_id)

        action_result.update_summary({"container_id": container_id})

        action_result.set_status(phantom.APP_SUCCESS)

    def _poll_now(self, param):

        # Connect to the server
        if (phantom.is_fail(self._connect_to_server(param))):
            return self.get_status()

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        # Get the maximum number of emails that we can pull, same as container count
        try:
            max_emails = int(param[phantom.APP_JSON_CONTAINER_COUNT])
        except:
            return self.set_status(phantom.APP_ERROR, "Invalid Container count")

        self.save_progress("POLL NOW Getting {0} most recent email uid(s)".format(max_emails))
        ret_val, ret_msg, email_ids = self._get_email_ids_to_process(max_emails, 1, config[IMAP_JSON_INGEST_MANNER])

        if (phantom.is_fail(ret_val)):
            return self.set_status(ret_val, ret_msg)

        if (not email_ids):
            return self.set_status(phantom.APP_SUCCESS)

        if (len(email_ids) != max_emails):
            self.save_progress("Got {0} recent emails".format(len(email_ids)))

        for i, email_id in enumerate(email_ids):
            self.send_progress("Parsing email uid: {0}".format(email_id))
            try:
                self._handle_email(email_id, param)
            except Exception as e:
                self.debug_print("ErrorExp in _handle_email # {0}".format(i), e)
                # continue to process the next email

        return self.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        if (param.get(phantom.APP_JSON_CONTAINER_COUNT) != MAX_COUNT_VALUE):
            return self._poll_now(param)

        # Connect to the server
        if (phantom.is_fail(self._connect_to_server(param))):
            return self.get_status()

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
            return self.set_status(ret_val, ret_msg)

        if (not email_ids):
            return self.set_status(phantom.APP_SUCCESS)

        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, IMAP_DEFAULT_CONTAINER_COUNT))

        if (container_count < len(email_ids)):
            self.save_progress("Trimming emails to process to {0}".format(container_count))
            email_ids = email_ids[-container_count:]

        for i, email_id in enumerate(email_ids):
            self.send_progress("Parsing email uid: {0}".format(email_id))
            try:
                self._handle_email(email_id, param)
            except Exception as e:
                self.debug_print("ErrorExp in _handle_email # {0}".format(i), e)
                return self.set_status(phantom.APP_ERROR)

        if (email_ids):
            self._state['next_muid'] = int(email_ids[-1]) + 1

        return self.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):

        # Connect to the server
        if (phantom.is_fail(self._connect_to_server(param))):
            self.append_to_message(IMAP_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        self.save_progress(IMAP_SUCC_CONNECTIVITY_TEST)

        return self.set_status(phantom.APP_SUCCESS, IMAP_SUCC_CONNECTIVITY_TEST)

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

    import sys
    import pudb

    pudb.set_trace()
    in_json = None
    in_email = None

    with open(sys.argv[1]) as f:

        in_json = f.read()
        in_json = json.loads(in_json)

        connector = ImapConnector()
        connector.print_progress_message = True

        data = in_json.get('data')
        raw_email = in_json.get('raw_email')

        # if neither present then treat it as a normal action test json
        if (not data and not raw_email):
            print(json.dumps(in_json, indent=4))
            result = connector._handle_action(json.dumps(in_json), None)
            print result
            exit(0)

        if (data):
            raw_email = data.get('raw_email')

        if (raw_email):
            config = {
                    "extract_attachments": True,
                    "extract_domains": True,
                    "extract_hashes": True,
                    "extract_ips": True,
                    "extract_urls": True }

            process_email = ProcessEmail()
            ret_val, message = process_email.process_email(connector, raw_email, "manual_parsing", config, None)

    exit(0)
