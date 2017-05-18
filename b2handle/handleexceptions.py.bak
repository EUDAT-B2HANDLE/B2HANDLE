'''
This module contains the exceptions that may occur in
libraries interacting with the Handle System.

Author: Merret Buurman (DKRZ), 2015-2016

'''
from __future__ import absolute_import
import json
import re
from .util import add_missing_optional_args_with_value_none

class BrokenHandleRecordException(Exception):

    def __init__(self, **args):

        # Default message:
        self.msg = 'Ill-formatted handle record'

        # Possible arguments:
        optional_args = ['msg', 'handle']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.handle is not None:
            self.msg += '\n\tHandle: '+self.handle

        super(self.__class__, self).__init__(self.msg)


class IllegalOperationException(Exception):
    '''
    To be raised when the user tries to create a HS_ADMIN self.handle,
    when he wants to create or remove 10320/loc entries using the
    wrong method, ...
    '''
    def __init__(self, **args):

        # Default message:
        self.msg = "Illegal Operation"

        # Possible arguments:
        optional_args = ['msg', 'handle', 'operation']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']
        self.operation = args['operation']

        if self.operation is not None:
            self.msg += ' ('+self.operation+')'
        if self.handle is not None:
            self.msg += ' on handle '+self.handle
        if self.custom_message is not None:
            self.msg += ': ' + self.custom_message
        self.msg += '.'

        super(self.__class__, self).__init__(self.msg)


class GenericHandleError(Exception):
    '''
    To be raised when the Handle Server returned an unexpected status code
    that does not map to any other specific exception.
    '''
    def __init__(self,**args):

        # Default message:
        self.msg = 'Error during interaction with Handle Server'

        # Possible arguments:
        optional_args = ['msg', 'handle','response', 'payload', 'operation']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']
        self.response = args['response']
        self.operation = args['operation']
        self.payload = args['payload']

        if self.operation is not None:
            self.msg += ' ('+self.operation+')'

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.handle is not None:
            self.msg += '\n\tHandle: '+self.handle

        if self.response is not None:
            self.msg += '\n\tURL: '+str(self.response.request.url)
            self.msg += '\n\tHTTP Status Code: '+str(self.response.status_code)
            self.msg += '\n\tResponse: '+str(self.response.content)

        if self.payload is not None:
            self.msg += '\n\tPayload: '+self.payload

        super(self.__class__, self).__init__(self.msg)

class ReverseLookupException(Exception):
    '''
    To be raised if the reverse lookup servlet returns an error.
    '''
    def __init__(self, **args):

        # Default message:
        self.msg = 'Error during Reverse Lookup'

        # Possible arguments:
        optional_args = ['msg', 'query','response']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.query = args['query']
        self.custom_message = args['msg']
        self.response = args['response']

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.query is not None:
            self.msg += '\n\tQuery: '+self.query

        if self.response is not None:
            pat = re.compile('>[\s]+<')
            responsecontent_less_whitespace = pat.sub('><', str(self.response.content))
            self.msg += '\n\tURL: '+str(self.response.request.url)
            self.msg += '\n\tHTTP Status Code: '+str(self.response.status_code)
            self.msg += '\n\tResponse: '+responsecontent_less_whitespace

        super(self.__class__, self).__init__(self.msg)
      

class HandleNotFoundException(Exception):
    '''
    To be raised if the self.handle was not found on the Handle Server.
    '''
    def __init__(self, **args):

        # Default message:
        self.msg ='Handle not found on server'

        # Possible arguments:
        optional_args = ['msg', 'handle','response']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']
        self.response = args['response']

        if self.handle is not None:
            self.msg = self.msg.replace('andle', 'andle '+self.handle)

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.response is not None:
            self.msg += '\n\tURL: '+str(self.response.request.url)
            self.msg += '\n\tHTTP Status Code: '+str(self.response.status_code)
            self.msg += '\n\tResponse: '+str(self.response.content)

        super(self.__class__, self).__init__(self.msg)

class HandleSyntaxError(Exception):
    '''
    To be raised if the Handle does not have correct syntax.
    '''
    def __init__(self, **args):

        # Default message:
        self.msg = 'Handle does not have expected syntax'

        # Possible arguments:
        optional_args = ['msg', 'handle','expected_syntax']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']
        self.expected_syntax = args['expected_syntax']

        if self.handle is not None:
            self.msg = self.msg.replace('andle', 'andle '+self.handle)

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.expected_syntax is not None:
            self.msg += '\n\tExpected: '+self.expected_syntax

        super(self.__class__, self).__init__(self.msg)

class HandleAlreadyExistsException(Exception):
    '''
    To be raised if self.handle already exists.
    '''
    def __init__(self, **args):

        # Default message:
        self.msg = 'Handle already exists'

        # Possible arguments:
        optional_args = ['msg', 'handle']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']

        if self.handle is not None:
            self.msg = self.msg.replace('andle', 'andle '+self.handle)

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        super(self.__class__, self).__init__(self.msg)

class HandleAuthenticationError(Exception):
    '''
    To be raised if authentication failed, if there was no
    write permission for creating, modifying, deleting.
    '''

    def __init__(self, **args):

        # Default message:
        self.msg = 'Insufficient permission'

        # Possible arguments:
        optional_args = ['msg', 'handle', 'operation', 'response', 'username']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.handle = args['handle']
        self.custom_message = args['msg']
        self.operation = args['operation']
        self.response = args['response']
        self.username = args['username']

        if self.operation is not None:
            self.msg += ' for '+self.operation

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.handle is not None:
            self.msg += '\n\tHandle: '+self.handle

        if self.username is not None:
            self.msg += '\n\tUsername: '+self.username

        if self.response is not None:
            self.msg += '\n\tURL: '+str(self.response.request.url)
            self.msg += '\n\tHTTP Status Code: '+str(self.response.status_code)
            self.msg += '\n\tResponse: '+str(self.response.content)

        super(self.__class__, self).__init__(self.msg)

class CredentialsFormatError(Exception):
    '''
    To be raised if credentials are ill-formatted or miss essential items.'''
    def __init__(self, **args):

        # Default message:
        self.msg = 'Problem with credentials'

        # Possible arguments:
        optional_args = ['msg']
        add_missing_optional_args_with_value_none(args, optional_args)
        self.custom_message = args['msg']

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        super(self.__class__, self).__init__(self.msg)
