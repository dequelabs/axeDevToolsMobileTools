#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

name: mobiletest.py
purpose: Test the python wrappers for the REST endpoints to the mobile server


Arguments:
    -s authserver - URL of the auth server to use, if not default
    -m mobileserver - URL of the mobile server to use, if not default
    Last Name


Dependencies:
    python 3.7

Created on Fri Apr 24 11:40:31 2020

@author: keithrhodes
"""

from __future__ import with_statement
import sys
import argparse
from urllib.parse import urlparse
import yaml
from mobile.mobile_admin import MobileAdmin
from mobile.mobile_exceptions import MobileConnectionError
from mobile.mobile_exceptions import MobileAuthenticationError
from mobile.mobile_exceptions import MobileGetError

DEFAULT_MOBILE_SERVER = "https://sauron.dequecloud.com/"
DEFAULT_KEYCLOAK_SERVER = "https://mobile-sso.dequelabs.com"

MOBILE_DEVTOOLS_CLIENT_ID = "mobile-private"
MOBILE_CLIENT_ID = "devtools-mobile"
MOBILE_REALM = "deque"


# perform login to Mobile as admin and return keycloak admin object
# args:
#   server - array of tuples that contain the URL, username, pw, client info to login
#               to the Mobile instance
def connect_mobile_as_admin(server, Mobileserver):

    Mobile_url = Mobileserver['URL']
    if 'Mobileport' in Mobileserver:
        Mobile_url += ':' + str(Mobileserver['Mobileport'])

    # Connect to Mobile admin interface
    try:
        if 'clientsecret' in server:
            Mobile_admin = MobileAdmin(
                                   auth_server_url=server['URL'] + "/auth/",
                                   server_url=Mobile_url,
                                   username=Mobileserver['user'],
                                   password=Mobileserver['password'],
                                   realm_name=Mobileserver['realm'],
                                   client_id=Mobileserver['clientid'],
                                   client_secret_key=Mobileserver['clientsecret'],
                                   verify=True,
                                   auto_refresh_token = [ 'get', 'post', 'put', 'delete' ] )
        else:
            Mobile_admin = MobileAdmin(
                                   auth_server_url=server['URL'] + "/auth/",
                                   server_url=Mobile_url,
                                   username=Mobileserver['user'],
                                   password=server['password'],
                                   realm_name=Mobileserver['realm'],
                                   client_id=Mobileserver['clientid'],
                                   verify=True,
                                   auto_refresh_token = [ 'get', 'post', 'put', 'delete' ] )

    except MobileConnectionError as error:
        print("Could not connect: " + error.error_message)
        sys.exit(1)
    except MobileAuthenticationError as error:
        print("Auth Error, " + error.error_message + " (" + str(error.response_code)+ ")")
        sys.exit(1)
    except MobileGetError as error:
        print("Could not connect, " + error.error_message + " (" + str(error.response_code)+ ")")
        sys.exit(1)

    return Mobile_admin



#find matchine server list entry from passed in server url
def find_server_in_list(server_data, server_url):
    locate_server = urlparse(server_url)

    for server in server_data['Servers']:
        if 'URL' in server:
            url_bits = urlparse(server['URL'])
            if locate_server[1] == url_bits[1]:
                if 'clientsecret' not in server:
                    if 'user' not in server:
                        print("username not found for: " + server_url)
                        return None
                    if 'password' not in server:
                        print("password not found for: " + server_url)
                        return None
                if 'realm' not in server:
                    print("realm not found for: " + server_url)
                    return None
                if 'clientid' not in server:
                    print("client not found for: " + server_url)
                    return None

                return server

    return None



#######################
#
#   Main entry point
#
#######################


def main():

    configfile = "mobileservers.yaml"

    #set up arguments
    parser = argparse.ArgumentParser(description='Import US Bank Users')
    parser.add_argument('-s', '--serverurl', type=str,
                        help='server to connect to if not default')
    parser.add_argument('-m', '--mobileurl', type=str,
                        help='server to connect to if not default')

    args = parser.parse_args()

    try:
        # Read json config file for list of keycloak servers
        with open(configfile) as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
    except:
        print("ERROR: YAML format of " + configfile + " is invalid (e.g. no tabs) - " + sys.exc_info()[0])
        sys.exit(1)

    if args.mobileurl is not None:
        mobile_server_url = args.mobileurl
    else:
        mobile_server_url = DEFAULT_MOBILE_SERVER

    if args.serverurl is not None:
        server_url = args.serverurl
    else:
        server_url = DEFAULT_KEYCLOAK_SERVER

    print("Connecting to requested servers...")

    # find keycloak auth server
    server = find_server_in_list(data, server_url)
    if server is None:
        print("Error finding server in list: " + server_url)
        sys.exit(1)

    # find mobile server
    mobileserver = find_server_in_list(data, mobile_server_url)
    if mobileserver is None:
        print("Error finding server in list: " + mobile_server_url)
        sys.exit(1)
    else:
        mobile_admin = connect_mobile_as_admin(server, mobileserver)

    userid = input('Enter Keycloak User id: ')
    package_name = input('Enter Package Name: ')
    resultid = input('Enter Result id: ')
    tags = input('Enter tags, seperated by commas: ')
    tag_list = tags.split(',')

    # get the scan for this result id
    try:
        result = mobile_admin.get_mobile_scan(userid, package_name, resultid)
    except MobileGetError as err_type:
        print("ERROR: " + err_type.error_message + " (" + str(err_type.response_code) + ")")
    else:
        print("Success retrieving scan; # results: {0} Title: {1}".format(len(result['axeRuleResults']),
                                       result['axeContext']['axeMetaData']['screenTitle']))

    # set a list of tags for the result id
    try:
        result = mobile_admin.set_mobile_scan_tag(userid, package_name, resultid, tag_list)
    except MobileGetError as err_type:
        print("ERROR: " + err_type.error_message + " (" + str(err_type.response_code) + ")")
    else:
        print("Success setting scan tags for result id: {0}".format(result['resultId']))


# Main entry point
if __name__ == "__main__":
    main()
