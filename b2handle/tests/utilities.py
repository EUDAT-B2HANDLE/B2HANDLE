import logging
import os

class NullHandler(logging.Handler):
    """
    For backward-compatibility with Python 2.6, a local class definition
    is used instead of logging.NullHandler
    """

    def emit(self, record):
        pass

REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.addHandler(NullHandler())

def get_this_directory(file_path_string, as_list=False):
    this_directory_string = os.path.split(os.path.realpath(file_path_string))[0]

    if as_list:
        this_directory_list = this_directory_string.split(os.path.sep)
        return this_directory_list
    else:
        return this_directory_string

def get_super_directory(file_path_string, as_list=False):
    this_directory_list = get_this_directory(file_path_string, as_list=True)
    super_directory_list = this_directory_list[0:len(this_directory_list)-1]

    if as_list:
        return super_directory_list
    else:
        super_directory_string = os.path.join(*super_directory_list)
        return '/'+super_directory_string


def get_neighbour_directory(file_path_string, dirname):
    super_directory_list = get_super_directory(file_path_string, as_list=True)
    super_directory_list.append(dirname)
    neighbour_directory_string = os.path.join(*super_directory_list)
    return '/'+neighbour_directory_string


def failure_message(expected, passed, methodname):
    msg = 'The PUT request payload that the method "'+methodname+ '" assembled differs from the expected. This does not necessarily mean that it is wrong, it might just be a different way to talking to the Handle Server. Please run an integration test to check this and update the exptected PUT request accordingly.\nCreated:  '+str(passed)+'\nExpected: '+str(expected)
    return msg

def replace_timestamps(jsonobject):
    ''' Replace timestamp values by "xxx" because their values do not matter.'''

    # Replace:
    if type(jsonobject) == type({}):
        if 'timestamp' in jsonobject:
            jsonobject['timestamp'] = 'xxx'

    # Recursion:
    if type(jsonobject) == type({'b':2}):
        for item in jsonobject.iteritems():
            replace_timestamps(item)

    elif type(jsonobject) == type([2,2]) or type(jsonobject) == type((2,2)):
        for item in jsonobject:
            replace_timestamps(item)

def log_new_test_case(name):
    REQUESTLOGGER.info('\n'+60*'*'+'\n*** '+name+'\n'+60*'*'+'\n')

def log_request_response_to_file(op, handle, url, head, veri, resp, payload=None):

    space = '\n   '
    message = ''
    message += op+' '+handle
    message += space+'URL:          '+url
    message += space+'HEADERS:      '+str(head)
    message += space+'VERIFY:       '+str(veri)
    if payload is not None:
        message += space+'PAYLOAD:'+space+str(payload)
    message += space+'RESPONSECODE: '+str(resp.status_code)
    message += space+'RESPONSE:'+space+str(resp.content)
    REQUESTLOGGER.info(message)

def log_start_test_code():
    REQUESTLOGGER.info('--->')

def log_end_test_code():
    REQUESTLOGGER.info('---<')

def sort_lists(jsonobject):

    # Sort:
    if type(jsonobject) == type([]):
        jsonobject.sort()

    # Recursion:
    if type(jsonobject) == type({'b':2}):
        for item in jsonobject.iteritems():
            sort_lists(item)

    elif type(jsonobject) == type([2,2]) or type(jsonobject) == type((2,2)):
        for item in jsonobject:
            sort_lists(item)
