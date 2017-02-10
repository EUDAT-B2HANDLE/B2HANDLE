import sys
from six import string_types
'''
This module provides some helper functions to ease porting the codebase 
     to Python 3.5..

'''
def check_response_content_type(response):
    if isinstance(response.content, string_types):
       return True

def decoded_response(response):
    if (check_response_content_type(response)):
        return response.content
    return response.content.decode('utf-8')

def set_encoding_variable():
    if sys.version_info > (3, 0):
       encoding_value = 'unicode'
    else:
       encoding_value = 'utf-8'
    return encoding_value
