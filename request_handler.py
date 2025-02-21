# File: request_handler.py
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

import base64
import json
import os

import encryption_helper
import requests
from django.http import HttpResponse

from imap_consts import *


def handle_request(request, path_parts):
    return IMAPRequestHandler(request, path_parts).handle_request()


def _get_dir_name_from_app_name(app_name):
    app_name = "".join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = "app_for_phantom"
    return app_name


class IMAPRequestHandler:
    def __init__(self, request, path_parts):
        self._request = request
        self._path_parts = path_parts
        self._rsh = None

    def _return_error(self, error_msg, status):
        state = self._rsh.load_app_state()
        state["error"] = True
        self._rsh.save_app_state(state)
        return HttpResponse(error_msg, status=status, content_type="text/plain")

    def _get_oauth_token(self, code):
        state = self._rsh.load_app_state()
        client_id = state["client_id"]
        redirect_uri = state["redirect_url"]
        client_secret = base64.b64decode(state["client_secret"]).decode()
        proxy = state["proxy"]
        token_url = state["token_url"]

        body = {
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code": code,
            "client_secret": client_secret,
        }

        try:
            r = requests.post(token_url, data=body, proxies=proxy, timeout=DEFAULT_REQUEST_TIMEOUT)
            r.raise_for_status()
            resp_json = r.json()
        except Exception as e:
            return False, self._return_error(f"Error retrieving OAuth Token: {e!s}", 401)
        state["oauth_token"] = resp_json
        state["is_encrypted"] = False
        self._rsh.save_app_state(state)

        return True, None

    def handle_request(self):
        try:
            GET = self._request.GET

            asset_id = GET.get("state")
            self._rsh = RequestStateHandler(asset_id)
            if not self._rsh.is_valid_asset_id(asset_id):
                return self._return_error("Invalid asset id provided", 401)

            error = GET.get("error")
            if error:
                error_msg = GET.get("error_description")
                return self._return_error(error_msg, 401)

            code = GET.get("code")
            ret_val, http_object = self._get_oauth_token(code)

            if ret_val is False:
                return http_object

            return HttpResponse("You can now close this page", content_type="text/plain")
        except Exception as e:
            return self._return_error(f"Error handling request: {e!s}", 400)


class RequestStateHandler:
    def __init__(self, asset_id):
        self._asset_id = asset_id

    def _get_state_file(self):
        dirpath = os.path.split(__file__)[0]
        state_file = f"{dirpath}/{self._asset_id}_state.json"
        return state_file

    @staticmethod
    def is_valid_asset_id(asset_id):
        """This function validates an asset id.
        Must be an alphanumeric string of less than 128 characters.

        :param asset_id: asset_id
        :return: is_valid: Boolean True if valid, False if not.
        """
        if isinstance(asset_id, str) and asset_id.isalnum() and len(asset_id) <= 128:
            return True
        return False

    def delete_state(self, connector):
        state_file = self._get_state_file()
        try:
            os.remove(state_file)
        except Exception as ex:
            if connector:
                connector.error_print(f"Error occurred while deleting state file: {ex!s}")

    def encrypt_state(self, state, connector=None):
        if state.get("is_encrypted"):
            return state

        try:
            if state.get("oauth_token") and state.get("oauth_token", {}).get("access_token"):
                state["oauth_token"]["access_token"] = encryption_helper.encrypt(state["oauth_token"]["access_token"], self._asset_id)
        except Exception as ex:
            if connector:
                connector.error_print(f"{IMAP_ENCRYPTION_ERROR}: {ex!s}")

        try:
            if state.get("oauth_token") and state.get("oauth_token", {}).get("refresh_token"):
                state["oauth_token"]["refresh_token"] = encryption_helper.encrypt(state["oauth_token"]["refresh_token"], self._asset_id)
        except Exception as ex:
            if connector:
                connector.error_print(f"{IMAP_ENCRYPTION_ERROR}: {ex!s}")
        state["is_encrypted"] = True
        return state

    def decrypt_state(self, state, connector=None):
        if not state.get("is_encrypted"):
            return state
        try:
            if state.get("oauth_token") and state.get("oauth_token", {}).get("access_token"):
                state["oauth_token"]["access_token"] = encryption_helper.decrypt(state["oauth_token"]["access_token"], self._asset_id)
        except Exception as ex:
            state["oauth_token"]["access_token"] = None
            if connector:
                connector.error_print(f"{IMAP_DECRYPTION_ERROR}: {ex!s}")

        try:
            if state.get("oauth_token") and state.get("oauth_token", {}).get("refresh_token"):
                state["oauth_token"]["refresh_token"] = encryption_helper.decrypt(state["oauth_token"]["refresh_token"], self._asset_id)
        except Exception as ex:
            state["oauth_token"]["refresh_token"] = None
            if connector:
                connector.error_print(f"{IMAP_DECRYPTION_ERROR}: {ex!s}")

        state["is_encrypted"] = False

        return state

    def save_app_state(self, state, connector=None):
        state = self.encrypt_state(state, connector)
        state_file = self._get_state_file()
        try:
            with open(state_file, "w+") as fp:
                fp.write(json.dumps(state))
        except Exception as ex:
            if connector:
                connector.error_print(f"Error occurred while saving state: {ex!s}")

        return True

    def load_app_state(self, connector=None, decrypt=True):
        state_file = self._get_state_file()
        state = {}
        try:
            with open(state_file) as fp:
                in_json = fp.read()
                state = json.loads(in_json)
        except Exception as ex:
            if connector:
                connector.error_print(f"Error occurred while saving state: {ex!s}")

        if not decrypt:
            return state
        state = self.decrypt_state(state, connector)
        return state
