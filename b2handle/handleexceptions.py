# This module contains the exceptions that may occur in libraries interacting with the Handle System.
# 
# Merret Buurman (DKRZ), 2015-07-14
# Last updated: 2015-08-26
import json

class BrokenHandleRecordException(Exception):

    def __init__(self, handle=None, custom_message=None):
        self.msg = 'Ill-formatted handle record'
        self.handle = handle
        self.custom_message = custom_message

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
    def __init__(self, operation=None, handle=None, custom_message=None):
        self.msg = "Illegal Operation"
        self.handle = handle
        self.custom_message = custom_message
        self.operation = operation

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
    def __init__(self, operation=None, handle=None, response=None, custom_message=None, payload=None):
        self.msg = 'Error during interaction with Handle Server'
        self.handle = handle
        self.custom_message = custom_message
        self.operation = operation
        self.response = response
        self.payload = payload

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
    def __init__(self, custom_message=None, query=None, response=None):
        self.msg = 'Error during Reverse Lookup'
        self.response = response
        self.query = query
        self.custom_message = custom_message

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if self.query is not None:
            self.msg += '\n\tQuery: '+self.query

        if self.response is not None:
            self.msg += '\n\tURL: '+str(self.response.request.url)
            self.msg += '\n\tHTTP Status Code: '+str(self.response.status_code)
            self.msg += '\n\tResponse: '+str(self.response.content)

        super(self.__class__, self).__init__(self.msg)
      

class HandleNotFoundException(Exception):
    '''
    To be raised if the self.handle was not found on the Handle Server.
    '''
    def __init__(self, handle=None, custom_message=None, response=None):
        self.msg ='Handle not found on server'
        self.handle = handle
        self.custom_message = custom_message
        self.response = response

        if self.handle is not None:
            self.msg = self.msg.replace('andle', 'andle '+self.handle)

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        if response is not None:
            self.msg += '\n\tURL: '+str(self.response.request.url)
            self.msg += '\n\tHTTP Status Code: '+str(self.response.status_code)
            self.msg += '\n\tResponse: '+str(self.response.content)

        super(self.__class__, self).__init__(self.msg)

class HandleSyntaxError(Exception):
    '''
    To be raised if the Handle does not have correct syntax.
    '''
    def __init__(self, custom_message=None, handle=None, expected_syntax=None):
        self.msg = 'Handle does not have expected syntax'
        self.handle = handle
        self.custom_message = custom_message
        self.expected_syntax = expected_syntax

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
    def __init__(self, handle=None, custom_message=None):
        self.msg = 'Handle already exists'
        self.handle = handle
        self.custom_message = custom_message

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

    def __init__(self, operation=None, handle=None, response=None, custom_message=None, username=None):
        self.msg = 'Insufficient permission'
        self.handle = handle
        self.custom_message = custom_message
        self.operation = operation
        self.response = response
        self.username = username

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
    def __init__(self, custom_message=None):
        self.msg = 'Ill-formatted credentials'
        self.custom_message = custom_message

        if self.custom_message is not None:
            self.msg += ': '+self.custom_message
        self.msg += '.'

        super(self.__class__, self).__init__(self.msg)
