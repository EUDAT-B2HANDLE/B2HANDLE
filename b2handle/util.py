'''
This module provides some functions that are
    needed across various modules of the
    b2handle library.
'''

import logging
import datetime

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
    if len(missing_args) > 0:
        raise ValueError('Missing mandatory arguments: '+', '.join(missing_args))
    else:
        return True

def get_valid_https_verify(value):
    '''
    Get a value that can be the boolean representation of a string
    or a boolean itself and returns It as a boolean.
    If this is not the case, It returns a string.

    :value: The HTTPS_verify input value
    :returns: True, False or a string.
    '''
    http_verify_value = value
    bool_values = {'false': False, 'true': True}

    if isinstance(value, bool):
        http_verify_value = value
    elif isinstance(value, str) and value.lower() in bool_values.keys():
        http_verify_value = bool_values[value.lower()]

    return http_verify_value

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
