'''
This module provides some handle-related functions
that are needed across various modules of the
b2handle library.
'''
from __future__ import absolute_import
import base64
from future.standard_library import install_aliases
install_aliases()
from urllib.parse import quote
from . import handleexceptions
from . import util

def remove_index_from_handle(handle_with_index):
    '''
    Returns index and handle separately, in a tuple.

    :handle_with_index: The handle string with an index (e.g.
        500:prefix/suffix)
    :return: index and handle as a tuple.
    '''

    split = handle_with_index.split(':')
    if len(split) == 2:
        split[0] = int(split[0])
        return split
    elif len(split) == 1:
        return (None, handle_with_index)
    elif len(split) > 2:
        raise handleexceptions.HandleSyntaxError(
            msg='Too many colons',
            handle=handle_with_index,
            expected_syntax='index:prefix/suffix')

def check_handle_syntax(string):
    '''
    Checks the syntax of a handle without an index (are prefix
    and suffix there, are there too many slashes?).

    :string: The handle without index, as string prefix/suffix.
    :raise: :exc:`~b2handle.handleexceptions.handleexceptions.HandleSyntaxError`
    :return: True. If it's not ok, exceptions are raised.

    '''

    expected = 'prefix/suffix'

    try:
        arr = string.split('/')
    except AttributeError:
        raise handleexceptions.HandleSyntaxError(msg='The provided handle is None', expected_syntax=expected)

    if len(arr) < 2:
        msg = 'No slash'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)

    if len(arr[0]) == 0:
        msg = 'Empty prefix'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)

    if len(arr[1]) == 0:
        msg = 'Empty suffix'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)

    if ':' in string:
        check_handle_syntax_with_index(string, base_already_checked=True)

    return True

def check_handle_syntax_with_index(string, base_already_checked=False):
    '''
    Checks the syntax of a handle with an index (is index there, is it an
    integer?), and of the handle itself.

    :string: The handle with index, as string index:prefix/suffix.
    :raise: :exc:`~b2handle.handleexceptions.handleexceptions.HandleSyntaxError`
    :return: True. If it's not ok, exceptions are raised.
    '''

    expected = 'index:prefix/suffix'
    try:
        arr = string.split(':')
    except AttributeError:
        raise handleexceptions.HandleSyntaxError(msg='The provided handle is None.', expected_syntax=expected)

    if len(arr) > 2:
        msg = 'Too many colons'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)
    elif len(arr) < 2:
        msg = 'No colon'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)
    try:
        int(arr[0])
    except ValueError:
        msg = 'Index is not an integer'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)

    if not base_already_checked:
        check_handle_syntax(string)
    return True

def create_authentication_string(username, password):
    '''
    Creates an authentication string from the username and password.

    :username: Username.
    :password: Password.
    :return: The encoded string.
    '''

    username_utf8 = username.encode('utf-8')
    userpw_utf8 = password.encode('utf-8')
    username_perc = quote(username_utf8)
    userpw_perc = quote(userpw_utf8)

    authinfostring = username_perc + ':' + userpw_perc
    authinfostring_base64 = base64.b64encode(authinfostring.encode('utf-8')).decode('utf-8')
    return authinfostring_base64

def make_request_log_message(**args):
    '''
    Creates a string containing all relevant information
    about a request made to the Handle System, for
    logging purposes.

    :handle: The handle that the request is about.
    :url: The url the request is sent to.
    :headers: The headers sent along with the request.
    :verify: Boolean parameter passed to the requests
        module (https verification).
    :resp: The request's response.
    :op: The library operation during which the request
        was sent.
    :payload: Optional. The payload sent with the request.
    :return: A formatted string.

    '''

    mandatory_args = ['op', 'handle', 'url', 'headers', 'verify', 'resp']
    optional_args = ['payload']
    util.check_presence_of_mandatory_args(args, mandatory_args)
    util.add_missing_optional_args_with_value_none(args, optional_args)

    space = '\n   '
    message = ''
    message += '\n'+args['op']+' '+args['handle']
    message += space+'URL:          '+args['url']
    message += space+'HEADERS:      '+str(args['headers'])
    message += space+'VERIFY:       '+str(args['verify'])
    if 'payload' in args.keys():
        message += space+'PAYLOAD:'+space+str(args['payload'])
    message += space+'RESPONSECODE: '+str(args['resp'].status_code)
    message += space+'RESPONSE:'+space+str(args['resp'].content)
    return message

