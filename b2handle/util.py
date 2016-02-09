'''
This module provides some functions that are
    needed across various modules of the
    b2handle library.
'''

import logging
import handleexceptions
import urllib
import base64


class NullHandler(logging.Handler):
    '''
    A NullHandler is used to be able to define loggers
        in library modules without logging to any target.
        The library user then defines the logging target by
        adding own Handler instances to the root logger.

    Please see the documentation of the logging module
        for help on logging.

    The NullHandler class is required when the library
        is run using Python 2.6. After this, the logging
        module contains a class NullHandler to use.
    '''
    def emit(self, record):
        pass

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(NullHandler())

def add_missing_optional_args_with_value_none(args, optional_args):
    '''
    Adds key-value pairs to the passed dictionary, so that
        afterwards, the dictionary can be used without needing
        to check for KeyErrors.

    If the keys passed as a second argument are not present,
        they are added with None as a value.

    :args: The dictionary to be completed.
    :optional_args: The keys that need to be added, if
        they are not present.
    :return: The modified dictionary.
    '''
      
    for name in optional_args:
        if not name in args.keys():
            args[name] = None
    return args

def remove_index_from_handle(handle_with_index):
    '''
    Returns index and handle separately, in a tuple.

    :handle_with_index: The handle string with an index (e.g.
        500:prefix/suffix)
    :return: index and handle as a tuple.
    '''

    split = handle_with_index.split(':')
    if len(split) == 2:
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

    if len(arr) > 2:
        msg = 'Too many slashes'
        raise handleexceptions.HandleSyntaxError(msg=msg, handle=string, expected_syntax=expected)
    elif len(arr) < 2:
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
    username_perc = urllib.quote(username_utf8)
    userpw_perc = urllib.quote(userpw_utf8)

    authinfostring = username_perc + ':' + userpw_perc
    authinfostring_base64 = base64.b64encode(authinfostring)
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
    check_presence_of_mandatory_args(args, mandatory_args)
    add_missing_optional_args_with_value_none(args, optional_args)

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

def check_presence_of_mandatory_args(args, mandatory_args):
    '''
    Checks whether all mandatory arguments are passed.

    This function aims at methods with many arguments
        which are passed as kwargs so that the order
        in which the are passed does not matter.

    :args: The dictionary passed as args.
    :mandatory_args: A list of keys that have to be
        present in the dictionary.
    :raise: :exc:`~ValueError`
    :returns: True, if all mandatory args are passed. If not,
        an exception is raised.

    '''
    missing_args = []
    for name in mandatory_args:
        if name not in args.keys():
            missing_args.append(name)
    if len(missing_args)>0:
        raise ValueError('Missing mandatory arguments: '+', '.join(missing_args))
    else:
        return True

def string_to_bool(string):
    '''
    Parses a string to a boolean. Accepts the words
        "true" and "false" in any mixture of capital
        andnon-capital letters. If the word is neither
        "true" nor "false", a KeyError is raised.

    :string: The string to parse. Passing a boolean
        does not harm.
    :returns: True or False.
    :raise: :exc:`~KeyError`
    '''

    dic = {'false':False, 'true':True}
    if string is True or string is False:
        return string
    else:
        return dic[string.lower()]

def log_instantiation(LOGGER, classname, args, forbidden, with_date=False):
    '''
    Log the instantiation of an object to the given logger.

    :LOGGER: A logger to log to. Please see module "logging".
    :classname: The name of the class that is being
        instantiated.
    :args: A dictionary of arguments passed to the instantiation,
        which will be logged on debug level.
    :forbidden: A list of arguments whose values should not be
        logged, e.g. "password".
    :with_date: Optional. Boolean. Indicated whether the initiation
        date and time should be logged.
    '''

    # Info:
    if with_date:
            LOGGER.info('Instantiating '+classname+' at '+datetime.datetime.now().strftime('%Y-%m-%d_%H:%M'))
    else:
        LOGGER.info('Instantiating '+classname)

    # Debug:
    for argname in args:
        if args[argname] is not None:
            if argname in forbidden:
                LOGGER.debug('Param '+argname+'*******')
            else:
                LOGGER.debug('Param '+argname+'='+str(args[argname]))

