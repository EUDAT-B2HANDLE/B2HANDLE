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
