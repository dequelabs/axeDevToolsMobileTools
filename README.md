# MobileTools
axe Mobile tools to demonstrate REST API's from python

---

This project provies a python wrapper to the axe DevTools Mobile server REST API.
It provides routines to perform the following operaitons:
1. Authenticate with the server
1. Retrieve scan data from the result key
1. Set tags for a scan based on the result key

Authentication information is stored in the file mobileservers.yaml and a prototype
file is provided in mobileservers.master.yaml, included in this package.

The current version requires username, password for authentication.


# First time setup

1. clone this repository (dequelabs/MobileTools)
1. Copy mobileservers.master.yaml to mobileservers.yaml
1. Edit mobileservers.yaml with text editor. You must fill out the "sauronprod" section. The 'user' and 'password' fields are for the user that will perform the operation. 
1. Install python 3.7 or above
1. Run: 'pip install -r requirements.txt' from a command/terminal window

# Endpoints

## MobileAdmin class

The constructor to the class takes the following arguments
.auth_server_url - default value provided in mobileservers.master.yaml
.server_url - default value provided in mobileservers.master.yaml
.username - your username for the server
.password - your password for the server
.realm_name - default value provided in mobileservers.master.yaml
.client_id - default value provided in mobileservers.master.yaml

**get_mobile_scan** - retrieve scan details from server

*parameters:*
-userid - keycloak user id for the user who owns the scan
-package_name - package name of the scan being retrieved
-resultid - result id key for the scan to retrieve

*returns:*
python dict with the details of the scan, including all passed and failed
rules, the platform the scan was run against, the list of applied tags.


**set_mobile_scan_tag** - set one or more tags for the scan identified with the input parameters

*parameters:*
-userid - keycloak user id for the user who owns the scan
-package_name - package name of the scan being retrieved
-resultid - result id key for the scan to retrieve
-tag_list - python list of tag names to apply to the scan

*returns:*
python dict with the details of the scan, including all passed and failed
rules, the platform the scan was run against, the list of applied tags.
