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

import requests

class MobileError(Exception):
    def __init__(self, error_message="", response_code=None,
                 response_body=None):

        Exception.__init__(self, error_message)

        self.response_code = response_code
        self.response_body = response_body
        self.error_message = error_message

    def __str__(self):
        if self.response_code is not None:
            return "{0}: {1}".format(self.response_code, self.error_message)
        else:
            return "{0}".format(self.error_message)


class MobileAuthenticationError(MobileError):
    pass


class MobileConnectionError(MobileError):
    pass


class MobileOperationError(MobileError):
    pass

class MobileRPTNotFound(MobileOperationError):
    pass

class MobileGetError(MobileOperationError):
    pass


class MobileAuthorizationConfigError(MobileOperationError):
    pass


class MobileInvalidTokenError(MobileOperationError):
    pass


def araise_error_from_response(response, error, expected_code=200, skip_exists=False):
    if expected_code == response.status_code:
        if expected_code == requests.codes.no_content:
            return {}

        try:
            return response.json()
        except ValueError:
            return response.content

    if skip_exists and response.status_code == 409:
        json_response = response.json()
        return {'code': json_response['code'], "message": "Already exists"}

    # retrieval call requested record that wasn't found
    if response.status_code == 404:
        return{}

    if response.status_code == 401:
         raise error(error_message="invalid user credentials",
                response_code=response.status_code)

    if response.status_code == 400:
        json_response = response.json()
        resp_dict = { 'code': json_response['code'] }
        return(resp_dict)
    elif response.status_code == 500:
        json_response = response.json()

    try:
        message = response.json()['message']
    except (KeyError, ValueError):
        error = MobileAuthenticationError
        message = "Authentication Error"

    if isinstance(error, dict):
        error = error.get(response.status_code, MobileOperationError)

    raise error(error_message=message,
                response_code=response.status_code,
                response_body=response.content)
