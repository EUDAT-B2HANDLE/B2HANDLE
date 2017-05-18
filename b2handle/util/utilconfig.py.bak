'''
This module provides functions to parse
and validate b2handle configuration
'''

def get_valid_https_verify(value):
    '''
    Get a value that can be the boolean representation of a string
    or a boolean itself and returns It as a boolean.
    If this is not the case, It returns a string.

    :value: The HTTPS_verify input value. A string can be passed as a path
            to a CA_BUNDLE certificate
    :returns: True, False or a string.
    '''
    http_verify_value = value
    bool_values = {'false': False, 'true': True}

    if isinstance(value, bool):
        http_verify_value = value
    elif (isinstance(value, str) or isinstance(value, unicode)) and value.lower() in bool_values.keys():
        http_verify_value = bool_values[value.lower()]

    return http_verify_value
