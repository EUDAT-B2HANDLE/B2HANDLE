import logging
import handleexceptions


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

h = NullHandler()

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(h)

def add_missing_optional_args_with_value_none(args, optional_args):
    if not type(args) == 'dict' and not type(optional_args)==list:
        if type(args) == list and type(optional_args) == dict:
            temp = optional_args
            optional_args = args
            args = temp
        else:
            raise ValueError('Wrong argument types for method "add_missing_optional_args_with_value_none"')
        
    for name in optional_args:
        if not name in args.keys():
            args[name] = None
    return args

def remove_index_from_handle(handle_with_index):
    '''
    Returns index and handle separately, in a tuple.

    :param handle_with_index: The handle string with an index (e.g.
        500:prefix/suffix)
    :return: index and handle as a tuple.
    '''

    LOGGER.debug('remove_index...')

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
    Checks the syntax of a handle without an index (are prefix and suffix
    there, are there too many slashes).

    :string: The handle without index, as string prefix/suffix.
    :raise: :exc:`~b2handle.handleexceptions.handleexceptions.HandleSyntaxError`
    :return: True. If it's not ok, exceptions are raised.

    '''

    LOGGER.debug('check_handle_syntax...')

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
    integer), and of the handle itself.
    
    :string: The handle with index, as string index:prefix/suffix.
    :raise: :exc:`~b2handle.handleexceptions.handleexceptions.HandleSyntaxError`
    :return: True. If it's not ok, exceptions are raised.
    '''

    LOGGER.debug('check_handle_syntax_with_index...')

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