'''
This module provides little helper functions that interpret
    the Handle Server's response codes and the HTTP status codes.
    All helpers functions test one possible outcome and return
    True or False.

Author: Merret Buurman (DKRZ), 2015-2016

'''

import json

def handle_success(response):
    if (response.status_code == 200 or response.status_code == 201) and json.loads(response.content)["responseCode"] == 1:
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
    if response.status_code == 401 or json.loads(response.content)["responseCode"] == 402:
        # need to put 'OR' because the HS responseCode is not always received!
        return True
    return False

def values_not_found(response):
    if response.status_code == 400 and json.loads(response.content)["responseCode"] == 200:
        return True
    return False

def handle_already_exists(response):
    if response.status_code == 409 & json.loads(response.content)["responseCode"] == 101:
        return True
    return False
