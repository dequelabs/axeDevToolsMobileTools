# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Unless otherwise stated in the comments, "id", in e.g. user_id, refers to the
# internal Keycloak server ID, usually a uuid string

from builtins import isinstance
from typing import Iterable
import datetime
import json

from .mobileconnection import MobileConnectionManager
from .mobile_exceptions import araise_error_from_response, MobileGetError
from .mobile_openid import MobileOpenID


class MobileAdmin:

    PAGE_SIZE = 100

    _server_url = None
    _username = None
    _password = None
    _realm_name = None
    _client_id = None
    _verify = None
    _client_secret_key = None
    _auto_refresh_token = None
    _connection = None
    _token = None
    _custom_headers = None
    _user_realm_name = None

    def __init__(self, auth_server_url, server_url, username=None, password=None, realm_name='master', client_id='admin-cli', verify=True,
                 client_secret_key=None, custom_headers=None, user_realm_name=None, auto_refresh_token=None):
        """

        :param auth_server_url: Keycloak server url
        :param server_url: Mobile server url
        :param username: admin username
        :param password: admin password
        :param realm_name: realm name
        :param client_id: client id
        :param verify: True if want check connection SSL
        :param client_secret_key: client secret key
        :param custom_headers: dict of custom header to pass to each HTML request
        :param user_realm_name: The realm name of the user, if different from realm_name
        :param auto_refresh_token: list of methods that allows automatic token refresh. ex: ['get', 'put', 'post', 'delete']
        """
        self.auth_server_url = auth_server_url
        self.server_url = server_url
        self.username = username
        self.password = password
        self.realm_name = realm_name
        self.client_id = client_id
        self.verify = verify
        self.client_secret_key = client_secret_key
        self.auto_refresh_token = auto_refresh_token or []
        self.user_realm_name = user_realm_name
        self.custom_headers = custom_headers
        self.last_refresh_token_timestamp = 0

        # Get token Admin
        self.get_token()

        self.last_refresh_token_timestamp = datetime.datetime.now()


    @property
    def server_url(self):
        return self._server_url

    @server_url.setter
    def server_url(self, value):
        self._server_url = value


    @property
    def auth_server_url(self):
        return self._auth_server_url

    @auth_server_url.setter
    def auth_server_url(self, value):
        self._auth_server_url = value

    @property
    def realm_name(self):
        return self._realm_name

    @realm_name.setter
    def realm_name(self, value):
        self._realm_name = value

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def verify(self):
        return self._verify

    @verify.setter
    def verify(self, value):
        self._verify = value

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value

    @property
    def auto_refresh_token(self):
        return self._auto_refresh_token

    @property
    def user_realm_name(self):
        return self._user_realm_name

    @user_realm_name.setter
    def user_realm_name(self, value):
        self._user_realm_name = value

    @property
    def custom_headers(self):
        return self._custom_headers

    @custom_headers.setter
    def custom_headers(self, value):
        self._custom_headers = value

    @auto_refresh_token.setter
    def auto_refresh_token(self, value):
        allowed_methods = {'get', 'post', 'put', 'delete'}
        if not isinstance(value, Iterable):
            raise TypeError('Expected a list of strings among {allowed}'.format(allowed=allowed_methods))
        if not all(method in allowed_methods for method in value):
            raise TypeError('Unexpected method in auto_refresh_token, accepted methods are {allowed}'.format(allowed=allowed_methods))

        self._auto_refresh_token = value


    def __fetch_all(self, url, query=None):
        '''Wrapper function to paginate GET requests

        :param url: The url on which the query is executed
        :param query: Existing query parameters (optional)

        :return: Combined results of paginated queries
        '''
        results = []

        # initalize query if it was called with None
        if not query:
            query = {}
        page = 0
        query['max'] = self.PAGE_SIZE

        # fetch until we can
        while True:
            query['first'] = page*self.PAGE_SIZE
            partial_results = araise_error_from_response(
                self.raw_get(url, **query),
                MobileGetError)
            if not partial_results:
                break
            results.extend(partial_results)
            page += 1
        return results

    def __fetch_page(self, url, query):
        ''' KAR: Wrapper function for *real* paginated GET requests
        '''
        results = []

        # initalize query if it was called with None
        if not query:
            return results

        results = araise_error_from_response(
                self.raw_get(url, **query),
                MobileGetError)
        return results


    def update_user_and_group(self, old_user_id, old_group_id, new_user_id, new_group_id, max_count):
        """
        Assign scan to user


        :return:  Mobile server response (RealmRepresentation)
        """
        params_path = { "oldid": old_user_id, "oldgroupid": old_group_id, "newuid": new_user_id, "groupid": new_group_id, "count": max_count }

        data_raw = self.raw_post("/admin/user/modify/{oldid}/{oldgroupid}?user-id={newuid}&org-id={groupid}&count={count}".format(**params_path), data=None)

        return araise_error_from_response(data_raw, MobileGetError, expected_code=200)


    def get_mobile_scan(self, user_id, package_name, result_id):
        """
        retrieve scan for user

        :return:  Mobile server response (scanResult)
        """
        params_path = { "userid": user_id, "packagename": package_name, "resultid": result_id }

        data_raw = self.raw_get("/attest/result/axe/{userid}/{packagename}/{resultid}".format(**params_path))

        return araise_error_from_response(data_raw, MobileGetError, expected_code=200)


    def set_mobile_scan_tag(self, user_id, package_name, result_id, tag_list):
        """
        set tag for scan

        :return:  Mobile server response
                    AxeResultKey {
                      String userId;
                      String packageName;
                      String resultId;
                    }
        """

        params_path = { "userid": user_id, "packagename": package_name, "resultid": result_id }

        data_raw = self.raw_post("/attest/result/tag/{userid}/{packagename}/{resultid}".format(**params_path), data=json.dumps(tag_list))

        return araise_error_from_response(data_raw, MobileGetError, expected_code=200)


    def raw_get(self, *args, **kwargs):
        """
        Calls connection.raw_get.

        If auto_refresh is set for *get* and *access_token* is expired, it will refresh the token
        and try *get* once more.
        """
        if 'get' in self.auto_refresh_token:
            self.validate_token()

        r = self.connection.raw_get(*args, **kwargs)

        return r

    def raw_post(self, *args, **kwargs):
        """
        Calls connection.raw_post.

        If auto_refresh is set for *post* and *access_token* is expired, it will refresh the token
        and try *post* once more.
        """
        if 'post' in self.auto_refresh_token:
            self.validate_token()

        r = self.connection.raw_post(*args, **kwargs)
        return r

    def raw_put(self, *args, **kwargs):
        """
        Calls connection.raw_put.

        If auto_refresh is set for *put* and *access_token* is expired, it will refresh the token
        and try *put* once more.
        """
        if 'put' in self.auto_refresh_token:
            self.validate_token()

        r = self.connection.raw_put(*args, **kwargs)
        return r

    def raw_delete(self, *args, **kwargs):
        """
        Calls connection.raw_delete.

        If auto_refresh is set for *delete* and *access_token* is expired, it will refresh the token
        and try *delete* once more.
        """
        if 'delete' in self.auto_refresh_token:
            self.validate_token()

        r = self.connection.raw_delete(*args, **kwargs)
        return r

    def get_token(self):
        self.mobile_openid = MobileOpenID(auth_server_url=self.auth_server_url, server_url=self.server_url, client_id=self.client_id,
                                              realm_name=self.user_realm_name or self.realm_name, verify=self.verify,
                                              client_secret_key=self.client_secret_key,
                                              custom_headers=self.custom_headers)

        grant_type = ["password"]
        #if self.client_secret_key:
        #    grant_type = ["client_credentials"]

        self._token = self.mobile_openid.token(self.username, self.password, grant_type=grant_type)

        headers = {
            'Authorization': 'Bearer ' + self.token.get('access_token'),
            'Content-Type': 'application/json'
        }

        if self.custom_headers is not None:
            # merge custom headers to main headers
            headers.update(self.custom_headers)

        self._connection = MobileConnectionManager(auth_base_url=self.auth_server_url,
                                             base_url=self.server_url,
                                             headers=headers,
                                             timeout=180,
                                             verify=self.verify)

    def refresh_token(self):
        refresh_token = self.token.get('refresh_token')
        try:
            self.token = self.mobile_openid.refresh_token(refresh_token)
            self.last_refresh_token_timestamp = datetime.datetime.now()
        except MobileGetError as e:
            if e.response_code == 400 and b'Refresh token expired' in e.response_body:
                self.get_token()
            else:
                raise
        self.connection.add_param_headers('Authorization', 'Bearer ' + self.token.get('access_token'))


    def validate_token(self):
        if 'expires_in' in self.token and self.last_refresh_token_timestamp != 0:
            expire_time =  self.last_refresh_token_timestamp + datetime.timedelta(seconds = self.token['expires_in'] )
            if expire_time <= datetime.datetime.now():
                self.refresh_token()
