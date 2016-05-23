'''
This module provides little helper functions that interpret
    the Handle Server's response codes and the HTTP status codes.
    All helpers functions test one possible outcome and return
    True or False.

Author: Merret Buurman (DKRZ), 2015-2016

'''

import json

def is_redirect_from_http_to_https(response):
    if response.status_code == 302:
        oldurl = response.url
        newurl = response.headers['location']
        if oldurl.startswith('http://') and oldurl.replace('http', 'https') == newurl:
            return True
    return False

def is_temporary_redirect(response):
    if response.status_code in [301, 302, 303, 307]:
        return True
    return False

def handle_success(response):
    # TODO May be misleading - 201 Created is also success!
    if response.status_code == 200 and json.loads(response.content)["responseCode"] == 1:
        return True
    return False

def does_handle_exist(response):
    if handle_success(response):
        return True
    return False

def is_handle_empty(response):
    if response.status_code == 200 and json.loads(response.content)["responseCode"] == 200:
        return True
    return False

def was_handle_created(response):
    if response.status_code == 201 and json.loads(response.content)["responseCode"] == 1:
        return True
    return False

def handle_not_found(response):
    if response.status_code == 404 and json.loads(response.content)["responseCode"] == 100:
        return True
    return False

def not_authenticated(response):
    try:
        if response.status_code == 401 or json.loads(response.content)["responseCode"] == 402:
            # need to put 'OR' because the HS responseCode is not always received!
            return True
    except ValueError as e: # If there is no JSON response.
        pass 
    return False

def values_not_found(response):
    if response.status_code == 400 and json.loads(response.content)["responseCode"] == 200:
        return True
    return False

def handle_already_exists(response):
    if response.status_code == 409 & json.loads(response.content)["responseCode"] == 101:
        return True
    return False