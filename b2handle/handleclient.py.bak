'''
This module provides the main client for the B2Handle
library.

Author: Merret Buurman (DKRZ), 2015-2016

'''
from __future__ import absolute_import
from past.builtins import xrange
# pylint handleclient.py --method-rgx="[a-z_][a-zA-Z0-9_]{2,30}$" --max-line-length=250 --variable-rgx="[a-z_][a-zA-Z0-9_]{2,30}$" --attr-rgx="[a-z_][a-zA-Z0-9_]{2,30}$" --argument-rgx="[a-z_][a-zA-Z0-9_]{2,30}$"

import json
import xml.etree.ElementTree as ET
import uuid
import logging
import datetime
from . import utilhandle
import requests  # This import is needed for mocking in unit tests.
from .handleexceptions import HandleNotFoundException
from .handleexceptions import GenericHandleError
from .handleexceptions import BrokenHandleRecordException
from .handleexceptions import HandleAlreadyExistsException
from .handleexceptions import IllegalOperationException
from .handlesystemconnector import HandleSystemConnector
from .searcher import Searcher
from . import hsresponses
from . import util
from b2handle.compatibility_helper import decoded_response, set_encoding_variable

      
# parameters for debugging
# LOG_FILENAME = 'example.log'
# logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(util.NullHandler())
REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.propagate = False
REQUESTLOGGER.addHandler(util.NullHandler())
encoding_value = set_encoding_variable()
class EUDATHandleClient(object):
    '''
    B2Handle main client class.
    (formerly B2SAFE epic client)
    '''

    # Instantiation:

    def __init__(self, handle_server_url=None, **args):
        '''
        Initialize the client. Depending on the arguments passed, it is set to
        read-only, write and/or search mode. All arguments are optional.
        If none is set, the client is in read-only mode, reading from
        the global handle resolver.

        :param handle_server_url: Optional. The URL of the Handle System
            server to read from. Defaults to 'https://hdl.handle.net'
        :param username: Optional. This must be a handle value reference in
            the format "index:prefix/suffix". The method will throw an exception
            upon bad syntax or non-existing Handle. The existence or validity
            of the password in the handle is not checked at this moment.
        :param password: Optional. This is the password stored as secret key
            in the actual Handle value the username points to.
        :param REST_API_url_extension: Optional. The extension of a Handle
            Server's URL to access its REST API. Defaults to '/api/handles/'.
        :param allowed_search_keys: Optional. The keys that can be used for
            reverse lookup of handles, as a list of strings. Defaults to 'URL'
            and 'CHECKSUM'. If the list is empty, all keys are passed to the
            reverse lookup servlet and exceptions are passed on to the user.
        :param 10320LOC_chooseby: Optional. The value to give to a handle
            record's 10320/LOC entry's 'chooseby' attribute as string (e.g.
            'locatt,weighted'). Defaults to None (attribute not set).
        :param modify_HS_ADMIN: Optional. Advanced usage. Determines whether
            the HS_ADMIN handle record entry can be modified using this library.
            Defaults to False and should not be modified.
        :param HTTPS_verify: Optional. This parameter can have three values.
            'True', 'False' or 'the path to a CA_BUNDLE file or directory with
            certificates of trusted CAs'. If set to False, the certificate is
            not verified in HTTP requests. Defaults to True.
        :param reverselookup_baseuri: Optional. The base URL of the reverse
            lookup service. If not set, the handle server base URL is used.
        :param reverselookup_url_extension: Optional. The path to append to
            the reverse lookup base URL to reach the reverse lookup service.
            Defaults to '/hrls/handles/'.
        :param handleowner: Optional. The username that will be given admin
            permissions over every newly created handle. By default, it is
            '200:0.NA/xyz' (where xyz is the prefix of the handle being created.
        :param HS_ADMIN_permissions: Optional. Advanced usage. This indicates
            the permissions that are given to the handle owner of newly
            created handles in the HS_ADMIN entry.
        :param private_key: Optional. The path to a file containing the private
            key that will be used for authentication in write mode. If this is
            specified, a certificate needs to be specified too.
        :param certificate_only: Optional. The path to a file containing the
            client certificate that will be used for authentication in write
            mode. If this is specified, a private key needs to be specified too.
        :param certificate_and_key: Optional. The path to a file containing both
            certificate and private key, used for authentication in write mode.
        '''

        util.log_instantiation(LOGGER, 'EUDATHandleClient', args, ['password', 'reverselookup_password'], with_date=True)

        LOGGER.debug('\n' + 60 * '*' + '\nInstantiation of EUDATHandleClient\n' + 60 * '*')

        args['handle_server_url'] = handle_server_url

        # Args that the constructor understands:
        self.__handleowner = None
        self.__HS_ADMIN_permissions = None
        self.__modify_HS_ADMIN = None
        self.__10320LOC_chooseby = None

        # Other attributes:
        self.__handlesystemconnector = HandleSystemConnector(handleclient=self, **args)
        self.__searcher = Searcher(handleclient=self, **args)

        # Defaults:
        defaults = {
            'HS_ADMIN_permissions':'011111110011',  # default from hdl-admintool
            'modify_HS_ADMIN': False
        }


        self.__store_args_or_set_to_defaults(args, defaults)


        LOGGER.debug(' - (end of initialisation)')

    def __store_args_or_set_to_defaults(self, args, defaults):

        # Needed for creating handles:

        if 'HS_ADMIN_permissions' in args.keys():
            self.__HS_ADMIN_permissions = args['HS_ADMIN_permissions']
            LOGGER.info(' - HS_ADMIN_permissions set to: ' + self.__HS_ADMIN_permissions)
        else:
            self.__HS_ADMIN_permissions = defaults['HS_ADMIN_permissions']
            LOGGER.info(' - HS_ADMIN_permissions set to default: ' + self.__HS_ADMIN_permissions)


        if '10320LOC_chooseby' in args.keys():
            self.__10320LOC_chooseby = args['10320LOC_chooseby']
            LOGGER.info(' - 10320LOC_chooseby set to: ' + self.__10320LOC_chooseby)
        else:
            LOGGER.info(' - 10320LOC_chooseby: No default.')


        if 'modify_HS_ADMIN' in args.keys():
            self.__modify_HS_ADMIN = args['modify_HS_ADMIN']
            LOGGER.info(' - modify_HS_ADMIN set to: ' + str(self.__modify_HS_ADMIN))
        else:
            self.__modify_HS_ADMIN = defaults['modify_HS_ADMIN']
            LOGGER.info(' - modify_HS_ADMIN set to default: ' + str(self.__modify_HS_ADMIN))


        # Handle owner: The user name to be written into HS_ADMIN.
        # Can be specified in json credentials file (optionally):
        if ('handleowner' in args.keys()) and (args['handleowner'] is not None):
            self.__handleowner = args['handleowner']
            LOGGER.info(' - handleowner set to: ' + self.__handleowner)
        else:
            self.__handleowner = None
            LOGGER.info(' - handleowner: Will be set to default for each created handle separately.')

    @staticmethod
    def instantiate_for_read_access(handle_server_url=None, **config):
        '''
        Initialize the client in read-only mode. Access is anonymous,
        thus no credentials are required.

        :param handle_server_url: Optional. The URL of the Handle System
            server to read from. Defaults to 'https://hdl.handle.net'
        :param \**config: More key-value pairs may be passed that will be passed
            on to the constructor as config. Config options from the
            credentials object are overwritten by this.
        :return: An instance of the client.
        '''

        inst = EUDATHandleClient(handle_server_url, **config)
        return inst

    @staticmethod
    def instantiate_for_read_and_search(handle_server_url, reverselookup_username, reverselookup_password, **config):
        '''
        Initialize client with read access and with search function.

        :param handle_server_url: The URL of the Handle Server. May be None
            (then, the default 'https://hdl.handle.net' is used).
        :param reverselookup_username: The username to authenticate at the
            reverse lookup servlet.
        :param reverselookup_password: The password to authenticate at the
            reverse lookup servlet.
        :param \**config: More key-value pairs may be passed that will be passed
            on to the constructor as config. Config options from the
            credentials object are overwritten by this.
        :return: An instance of the client.
        '''

        if handle_server_url is None and 'reverselookup_baseuri' not in config.keys():
            raise TypeError('You must specify either "handle_server_url" or "reverselookup_baseuri".' + \
                ' Searching not possible without the URL of a search servlet.')

        inst = EUDATHandleClient(
            handle_server_url,
            reverselookup_username=reverselookup_username,
            reverselookup_password=reverselookup_password,
            **config
        )
        return inst

    @staticmethod
    def instantiate_with_username_and_password(handle_server_url, username, password, **config):
        '''
        Initialize client against an HSv8 instance with full read/write access.

        The method will throw an exception upon bad syntax or non-existing
        Handle. The existence or validity of the password in the handle is
        not checked at this moment.

        :param handle_server_url: The URL of the Handle System server.
        :param username: This must be a handle value reference in the format
            "index:prefix/suffix".
        :param password: This is the password stored as secret key in the
            actual Handle value the username points to.
        :param \**config: More key-value pairs may be passed that will be passed
            on to the constructor as config.
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`: If the username handle is not found.
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :return: An instance of the client.
        '''

        inst = EUDATHandleClient(handle_server_url, username=username, password=password, **config)
        return inst

    @staticmethod
    def instantiate_with_credentials(credentials, **config):
        '''
        Initialize the client against an HSv8 instance with full read/write
        access.

        :param credentials: A credentials object, see separate class
            PIDClientCredentials.
        :param \**config: More key-value pairs may be passed that will be passed
            on to the constructor as config. Config options from the
            credentials object are overwritten by this.
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`: If the username handle is not found.
        :return: An instance of the client.
        '''
        key_value_pairs = credentials.get_all_args()

        if config is not None:
            key_value_pairs.update(**config)  # passed config overrides json file

        inst = EUDATHandleClient(**key_value_pairs)
        return inst

    # Methods with read access to Handle Server:

    def retrieve_handle_record_json(self, handle):
        '''
        Retrieve a handle record from the Handle server as a complete nested
        dict (including index, ttl, timestamp, ...) for later use.

        Note: For retrieving a simple dict with only the keys and values,
        please use :meth:`~b2handle.handleclient.EUDATHandleClient.retrieve_handle_record`.

        :param handle: The Handle whose record to retrieve.
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :return: The handle record as a nested dict. If the handle does not
            exist, returns None.
        '''
        LOGGER.debug('retrieve_handle_record_json...')

        utilhandle.check_handle_syntax(handle)
        response = self.__send_handle_get_request(handle)
        response_content = decoded_response(response)
                    
        if hsresponses.handle_not_found(response):
            return None
        elif hsresponses.does_handle_exist(response):
         
            handlerecord_json = json.loads(response_content)
            if not handlerecord_json['handle'] == handle:
                raise GenericHandleError(
                    operation='retrieving handle record',
                    handle=handle,
                    response=response,
                    custom_message='The retrieve returned a different handle than was asked for.'
                )
            return handlerecord_json
        elif hsresponses.is_handle_empty(response):
            handlerecord_json = json.loads(response_content)
            return handlerecord_json
        else:
            raise GenericHandleError(
                operation='retrieving',
                handle=handle,
                response=response
            )
           
        
    def retrieve_handle_record(self, handle, handlerecord_json=None):
        '''
        Retrieve a handle record from the Handle server as a dict. If there
        is several entries of the same type, only the first one is
        returned. Values of complex types (such as HS_ADMIN) are
        transformed to strings.

        :param handle: The handle whose record to retrieve.
        :param handlerecord_json: Optional. If the handlerecord has already
            been retrieved from the server, it can be reused.
        :return: A dict where the keys are keys from the Handle record (except
            for hidden entries) and every value is a string. The result will be
            None if the Handle does not exist.
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        '''
        LOGGER.debug('retrieve_handle_record...')

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            return None  # Instead of HandleNotFoundException!
        list_of_entries = handlerecord_json['values']

        record_as_dict = {}
        for entry in list_of_entries:
            key = entry['type']
            if not key in record_as_dict.keys():
                record_as_dict[key] = str(entry['data']['value'])
        return record_as_dict

    def get_value_from_handle(self, handle, key, handlerecord_json=None):
        '''
        Retrieve a single value from a single Handle. If several entries with
        this key exist, the methods returns the first one. If the handle
        does not exist, the method will raise a HandleNotFoundException.

        :param handle: The handle to take the value from.
        :param key: The key.
        :return: A string containing the value or None if the Handle record
         does not contain the key.
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        '''
        LOGGER.debug('get_value_from_handle...')

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            raise HandleNotFoundException(handle=handle)
        list_of_entries = handlerecord_json['values']

        indices = []
        for i in xrange(len(list_of_entries)):
            if list_of_entries[i]['type'] == key:
                indices.append(i)

        if len(indices) == 0:
            return None
        else:
            if len(indices) > 1:
                LOGGER.debug('get_value_from_handle: The handle ' + handle + \
                    ' contains several entries of type "' + key + \
                    '". Only the first one is returned.')
            return list_of_entries[indices[0]]['data']['value']

    def is_10320LOC_empty(self, handle, handlerecord_json=None):
        '''
        Checks if there is a 10320/LOC entry in the handle record.
        *Note:* In the unlikely case that there is a 10320/LOC entry, but it does
        not contain any locations, it is treated as if there was none.

        :param handle: The handle.
        :param handlerecord_json: Optional. The content of the response of a
            GET request for the handle as a dict. Avoids another GET request.
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :return: True if the record contains NO 10320/LOC entry; False if it
            does contain one.
        '''
        LOGGER.debug('is_10320LOC_empty...')

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            raise HandleNotFoundException(handle=handle)
        list_of_entries = handlerecord_json['values']

        num_entries = 0
        num_URL = 0
        for entry in list_of_entries:
            if entry['type'] == '10320/LOC':
                num_entries += 1
                xmlroot = ET.fromstring(entry['data']['value'])
                list_of_locations = xmlroot.findall('location')
                for item in list_of_locations:
                    if item.get('href') is not None:
                        num_URL += 1
        if num_entries == 0:
            return True
        else:
            if num_URL == 0:
                return True
            else:
                return False

    def is_URL_contained_in_10320LOC(self, handle, url, handlerecord_json=None):
        '''
        Checks if the URL is already present in the handle record's
        10320/LOC entry.

        :param handle: The handle.
        :param url: The URL.
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :return: True if the handle record's 10320/LOC entry contains the URL;
            False otherwise. If the entry is empty or does not exist, False
            is returned.
        '''
        LOGGER.debug('is_URL_contained_in_10320LOC...')

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            raise HandleNotFoundException(handle=handle)
        list_of_entries = handlerecord_json['values']

        num_entries = 0
        num_URL = 0
        for entry in list_of_entries:
            if entry['type'] == '10320/LOC':
                num_entries += 1
                xmlroot = ET.fromstring(entry['data']['value'])
                list_of_locations = xmlroot.findall('location')
                for item in list_of_locations:
                    if item.get('href') == url:
                        num_URL += 1

        if num_entries == 0:
            return False
        else:
            if num_URL == 0:
                return False
            else:
                return True

    # Methods with write access to Handle Server:

    def generate_and_register_handle(self, prefix, location, checksum=None, additional_URLs=None, **extratypes):
        '''
        Register a new Handle with a unique random name (random UUID).

        :param prefix: The prefix of the handle to be registered. The method
            will generate a suffix.
        :param location: The URL of the data entity to be referenced.
        :param checksum: Optional. The checksum string.
        :param extratypes: Optional. Additional key value pairs as dict.
        :param additional_URLs: Optional. A list of URLs (as strings) to be
            added to the handle record as 10320/LOC entry.
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        :return: The new handle name.
        '''

        LOGGER.debug('generate_and_register_handle...')

        handle = self.generate_PID_name(prefix)
        handle = self.register_handle(
            handle,
            location,
            checksum,
            additional_URLs,
            overwrite=True,
            **extratypes
        )
        return handle

    def modify_handle_value(self, handle, ttl=None, add_if_not_exist=True, **kvpairs):
        '''
        Modify entries (key-value-pairs) in a handle record. If the key
        does not exist yet, it is created.

        *Note:* We assume that a key exists only once. In case a key exists
        several time, an exception will be raised.

        *Note:* To modify 10320/LOC, please use :meth:`~b2handle.handleclient.EUDATHandleClient.add_additional_URL` or
        :meth:`~b2handle.handleclient.EUDATHandleClient.remove_additional_URL`.

        :param handle: Handle whose record is to be modified
        :param ttl: Optional. Integer value. If ttl should be set to a
            non-default value.
        :param all other args: The user can specify several key-value-pairs.
            These will be the handle value types and values that will be
            modified. The keys are the names or the handle value types (e.g.
            "URL"). The values are the new values to store in "data". If the
            key is 'HS_ADMIN', the new value needs to be of the form
            {'handle':'xyz', 'index':xyz}. The permissions will be set to the
            default permissions.
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        '''
        LOGGER.debug('modify_handle_value...')

        # Read handle record:
        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot modify unexisting handle'
            raise HandleNotFoundException(handle=handle, msg=msg)
        list_of_entries = handlerecord_json['values']

        # HS_ADMIN
        if 'HS_ADMIN' in kvpairs.keys() and not self.__modify_HS_ADMIN:
            msg = 'You may not modify HS_ADMIN'
            raise IllegalOperationException(
                msg=msg,
                operation='modifying HS_ADMIN',
                handle=handle
            )

        nothingchanged = True
        new_list_of_entries = []
        list_of_old_and_new_entries = list_of_entries[:]
        keys = kvpairs.keys()
        for key, newval in kvpairs.items():
            # Change existing entry:
            changed = False
            for i in xrange(len(list_of_entries)):
                if list_of_entries[i]['type'] == key:
                    if not changed:
                        list_of_entries[i]['data'] = newval
                        list_of_entries[i].pop('timestamp')  # will be ignored anyway
                        if key == 'HS_ADMIN':
                            newval['permissions'] = self.__HS_ADMIN_permissions
                            list_of_entries[i].pop('timestamp')  # will be ignored anyway
                            list_of_entries[i]['data'] = {
                                'format':'admin',
                                'value':newval
                            }
                            LOGGER.info('Modified' + \
                                ' "HS_ADMIN" of handle ' + handle)
                        changed = True
                        nothingchanged = False
                        new_list_of_entries.append(list_of_entries[i])
                        list_of_old_and_new_entries.append(list_of_entries[i])
                    else:
                        msg = 'There is several entries of type "' + key + '".' + \
                            ' This can lead to unexpected behaviour.' + \
                            ' Please clean up before modifying the record.'
                        raise BrokenHandleRecordException(handle=handle, msg=msg)

            # If the entry doesn't exist yet, add it:
            if not changed:
                if add_if_not_exist:
                    LOGGER.debug('modify_handle_value: Adding entry "' + key + '"' + \
                        ' to handle ' + handle)
                    index = self.__make_another_index(list_of_old_and_new_entries)
                    entry_to_add = self.__create_entry(key, newval, index, ttl)
                    new_list_of_entries.append(entry_to_add)
                    list_of_old_and_new_entries.append(entry_to_add)
                    changed = True
                    nothingchanged = False

        # Add the indices
        indices = []
        for i in xrange(len(new_list_of_entries)):
            indices.append(new_list_of_entries[i]['index'])

        # append to the old record:
        if nothingchanged:
            LOGGER.debug('modify_handle_value: There was no entries ' + \
                str(kvpairs.keys()) + ' to be modified (handle ' + handle + ').' + \
                ' To add them, set add_if_not_exist = True')
        else:
            op = 'modifying handle values'
            resp, put_payload = self.__send_handle_put_request(
                handle,
                new_list_of_entries,
                indices=indices,
                overwrite=True,
                op=op)
            if hsresponses.handle_success(resp):
                LOGGER.info('Handle modified: ' + handle)
            else:
                msg = 'Values: ' + str(kvpairs)
                raise GenericHandleError(
                    operation=op,
                    handle=handle,
                    response=resp,
                    msg=msg,
                    payload=put_payload
                )

    def delete_handle_value(self, handle, key):
        '''
        Delete a key-value pair from a handle record. If the key exists more
        than once, all key-value pairs with this key are deleted.

        :param handle: Handle from whose record the entry should be deleted.
        :param key: Key to be deleted. Also accepts a list of keys.
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        '''
        LOGGER.debug('delete_handle_value...')

        # read handle record:
        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot modify unexisting handle'
            raise HandleNotFoundException(handle=handle, msg=msg)
        list_of_entries = handlerecord_json['values']


        # find indices to delete:
        keys = None
        indices = []
        if type(key) != type([]):
            keys = [key]
        else:
            keys = key
        keys_done = []
        for key in keys:

            # filter HS_ADMIN
            if key == 'HS_ADMIN':
                op = 'deleting "HS_ADMIN"'
                raise IllegalOperationException(operation=op, handle=handle)

            if key not in keys_done:
                indices_onekey = self.get_handlerecord_indices_for_key(key, list_of_entries)
                indices = indices + indices_onekey
                keys_done.append(key)

        # Important: If key not found, do not continue, as deleting without indices would delete the entire handle!!
        if not len(indices) > 0:
            LOGGER.debug('delete_handle_value: No values for key(s) ' + str(keys))
            return None
        else:

            # delete and process response:
            op = 'deleting "' + str(keys) + '"'
            resp = self.__send_handle_delete_request(handle, indices=indices, op=op)
            if hsresponses.handle_success(resp):
                LOGGER.debug("delete_handle_value: Deleted handle values " + str(keys) + "of handle " + handle)
            elif hsresponses.values_not_found(resp):
                pass
            else:
                raise GenericHandleError(
                    operation=op,
                    handle=handle,
                    response=resp
                )

    def delete_handle(self, handle, *other):
        '''Delete the handle and its handle record. If the Handle is not found, an Exception is raised.

        :param handle: Handle to be deleted.
        :param other: Deprecated. This only exists to catch wrong method usage
            by users who are used to delete handle VALUES with the method.
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        '''

        LOGGER.debug('delete_handle...')

        utilhandle.check_handle_syntax(handle)

        # Safety check. In old epic client, the method could be used for
        # deleting handle values (not entire handle) by specifying more
        # parameters.
        if len(other) > 0:
            message = 'You specified more than one argument. If you wanted' + \
                ' to delete just some values from a handle, please use the' + \
                ' new method "delete_handle_value()".'
            raise TypeError(message)

        op = 'deleting handle'
        resp = self.__send_handle_delete_request(handle, op=op)
        if hsresponses.handle_success(resp):
            LOGGER.info('Handle ' + handle + ' deleted.')
        elif hsresponses.handle_not_found(resp):
            msg = ('delete_handle: Handle ' + handle + ' did not exist, '
                   'so it could not be deleted.')
            LOGGER.debug(msg)
            raise HandleNotFoundException(msg=msg, handle=handle, response=resp)
        else:
            raise GenericHandleError(op=op, handle=handle, response=resp)

    def exchange_additional_URL(self, handle, old, new):
        '''
        Exchange an URL in the 10320/LOC entry against another, keeping the same id
        and other attributes.

        :param handle: The handle to modify.
        :param old: The URL to replace.
        :param new: The URL to set as new URL.
        '''
        LOGGER.debug('exchange_additional_URL...')

        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot exchange URLs in unexisting handle'
            raise HandleNotFoundException(
                handle=handle,
                msg=msg
            )
        list_of_entries = handlerecord_json['values']

        if not self.is_URL_contained_in_10320LOC(handle, old, handlerecord_json):
            LOGGER.debug('exchange_additional_URL: No URLs exchanged, as the url was not in the record.')
        else:
            self.__exchange_URL_in_13020loc(old, new, list_of_entries, handle)

            op = 'exchanging URLs'
            resp, put_payload = self.__send_handle_put_request(
                handle,
                list_of_entries,
                overwrite=True,
                op=op
            )
            # TODO FIXME (one day): Implement overwriting by index (less risky)
            if hsresponses.handle_success(resp):
                pass
            else:
                msg = 'Could not exchange URL ' + str(old) + ' against ' + str(new)
                raise GenericHandleError(
                    operation=op,
                    handle=handle,
                    reponse=resp,
                    msg=msg,
                    payload=put_payload
                )

    def add_additional_URL(self, handle, *urls, **attributes):
        '''
        Add a URL entry to the handle record's 10320/LOC entry. If 10320/LOC
        does not exist yet, it is created. If the 10320/LOC entry already
        contains the URL, it is not added a second time.

        :param handle: The handle to add the URL to.
        :param urls: The URL(s) to be added. Several URLs may be specified.
        :param attributes: Optional. Additional key-value pairs to set as
            attributes to the <location> elements, e.g. weight, http_role or
            custom attributes. Note: If the URL already exists but the
            attributes are different, they are updated!
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        '''
        LOGGER.debug('add_additional_URL...')

        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot add URLS to unexisting handle!'
            raise HandleNotFoundException(handle=handle, msg=msg)
        list_of_entries = handlerecord_json['values']

        is_new = False
        for url in urls:
            if not self.is_URL_contained_in_10320LOC(handle, url, handlerecord_json):
                is_new = True

        if not is_new:
            LOGGER.debug("add_additional_URL: No new URL to be added (so no URL is added at all).")
        else:

            for url in urls:
                self.__add_URL_to_10320LOC(url, list_of_entries, handle)

            op = 'adding URLs'
            resp, put_payload = self.__send_handle_put_request(handle, list_of_entries, overwrite=True, op=op)
            # TODO FIXME (one day) Overwrite by index.

            if hsresponses.handle_success(resp):
                pass
            else:
                msg = 'Could not add URLs ' + str(urls)
                raise GenericHandleError(
                    operation=op,
                    handle=handle,
                    reponse=resp,
                    msg=msg,
                    payload=put_payload
                )

    def remove_additional_URL(self, handle, *urls):
        '''
        Remove a URL from the handle record's 10320/LOC entry.

        :param handle: The handle to modify.
        :param urls: The URL(s) to be removed. Several URLs may be specified.
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        '''

        LOGGER.debug('remove_additional_URL...')

        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot remove URLs from unexisting handle'
            raise HandleNotFoundException(handle=handle, msg=msg)
        list_of_entries = handlerecord_json['values']

        for url in urls:
            self.__remove_URL_from_10320LOC(url, list_of_entries, handle)

        op = 'removing URLs'
        resp, put_payload = self.__send_handle_put_request(
            handle,
            list_of_entries,
            overwrite=True,
            op=op
        )
        # TODO FIXME (one day): Implement overwriting by index (less risky),
        # once HS have fixed the issue with the indices.
        if hsresponses.handle_success(resp):
            pass
        else:
            op = 'removing "' + str(urls) + '"'
            msg = 'Could not remove URLs ' + str(urls)
            raise GenericHandleError(
                operation=op,
                handle=handle,
                reponse=resp,
                msg=msg,
                payload=put_payload
            )

    def register_handle(self, handle, location, checksum=None, additional_URLs=None, overwrite=False, **extratypes):
        '''
        Registers a new Handle with given name. If the handle already exists
        and overwrite is not set to True, the method will throw an
        exception.

        :param handle: The full name of the handle to be registered (prefix
            and suffix)
        :param location: The URL of the data entity to be referenced
        :param checksum: Optional. The checksum string.
        :param extratypes: Optional. Additional key value pairs.
        :param additional_URLs: Optional. A list of URLs (as strings) to be
            added to the handle record as 10320/LOC entry.
        :param overwrite: Optional. If set to True, an existing handle record
            will be overwritten. Defaults to False.
        :raises: :exc:`~b2handle.handleexceptions.HandleAlreadyExistsException` Only if overwrite is not set or
            set to False.
        :raises: :exc:`~b2handle.handleexceptions.HandleAuthenticationError`
        :raises: :exc:`~b2handle.handleexceptions.HandleSyntaxError`
        :return: The handle name.
        '''
        LOGGER.debug('register_handle...')

        # If already exists and can't be overwritten:
        if overwrite == False:
            handlerecord_json = self.retrieve_handle_record_json(handle)
            if handlerecord_json is not None:
                msg = 'Could not register handle'
                LOGGER.error(msg + ', as it already exists.')
                raise HandleAlreadyExistsException(handle=handle, msg=msg)

        # Create admin entry
        list_of_entries = []
        adminentry = self.__create_admin_entry(
            self.__handleowner,
            self.__HS_ADMIN_permissions,
            self.__make_another_index(list_of_entries, hs_admin=True),
            handle
        )
        list_of_entries.append(adminentry)

        # Create other entries
        entry_URL = self.__create_entry(
            'URL',
            location,
            self.__make_another_index(list_of_entries, url=True)
        )
        list_of_entries.append(entry_URL)
        if checksum is not None:
            entryChecksum = self.__create_entry(
                'CHECKSUM',
                checksum,
                self.__make_another_index(list_of_entries)
            )
            list_of_entries.append(entryChecksum)
        if extratypes is not None:
            for key, value in extratypes.items():
                entry = self.__create_entry(
                    key,
                    value,
                    self.__make_another_index(list_of_entries)
                )
                list_of_entries.append(entry)
        if additional_URLs is not None and len(additional_URLs) > 0:
            for url in additional_URLs:
                self.__add_URL_to_10320LOC(url, list_of_entries, handle)

        # Create record itself and put to server
        op = 'registering handle'
        resp, put_payload = self.__send_handle_put_request(
            handle,
            list_of_entries,
            overwrite=overwrite,
            op=op
        )
        resp_content = decoded_response(resp)
        if hsresponses.was_handle_created(resp) or hsresponses.handle_success(resp):
            LOGGER.info("Handle registered: " + handle)
            return json.loads(resp_content)['handle']
        elif hsresponses.is_temporary_redirect(resp):
            oldurl = resp.url
            newurl = resp.headers['location']
            raise GenericHandleError(
                operation=op,
                handle=handle,
                response=resp,
                payload=put_payload,
                msg='Temporary redirect from ' + oldurl + ' to ' + newurl + '.'
            )
        elif hsresponses.handle_not_found(resp):
            raise GenericHandleError(
                operation=op,
                handle=handle,
                response=resp,
                payload=put_payload,
                msg='Could not create handle. Possibly you used HTTP instead of HTTPS?'
            )
        else:
            raise GenericHandleError(
                operation=op,
                handle=handle,
                reponse=resp,
                payload=put_payload
            )

    # No HS access:

    def search_handle(self, URL=None, prefix=None, **key_value_pairs):
        '''
        Search for handles containing the specified key with the specified
        value. The search terms are passed on to the reverse lookup servlet
        as-is. The servlet is supposed to be case-insensitive, but if it
        isn't, the wrong case will cause a :exc:`~b2handle.handleexceptions.ReverseLookupException`.

        *Note:* If allowed search keys are configured, only these are used. If
        no allowed search keys are specified, all key-value pairs are
        passed on to the reverse lookup servlet, possibly causing a
        :exc:`~b2handle.handleexceptions.ReverseLookupException`.

        Example calls:

            .. code:: python

                list_of_handles = search_handle('http://www.foo.com')
                list_of_handles = search_handle('http://www.foo.com', CHECKSUM=99999)
                list_of_handles = search_handle(URL='http://www.foo.com', CHECKSUM=99999)


        :param URL: Optional. The URL to search for (reverse lookup). [This is
            NOT the URL of the search servlet!]
        :param prefix: Optional. The Handle prefix to which the search should
            be limited to. If unspecified, the method will search across all
            prefixes present at the server given to the constructor.
        :param key_value_pairs: Optional. Several search fields and values can
            be specified as key-value-pairs,
            e.g. CHECKSUM=123456, URL=www.foo.com
        :raise: :exc:`~b2handle.handleexceptions.ReverseLookupException`: If a search field is specified that
            cannot be used, or if something else goes wrong.
        :return: A list of all Handles (strings) that bear the given key with
            given value of given prefix or server. The list may be empty and
            may also contain more than one element.
        '''
        LOGGER.debug('search_handle...')

        list_of_handles = self.__searcher.search_handle(URL=URL, prefix=prefix, **key_value_pairs)

        return list_of_handles

    def generate_PID_name(self, prefix=None):
        '''
        Generate a unique random Handle name (random UUID). The Handle is not
        registered. If a prefix is specified, the PID name has the syntax
        <prefix>/<generatedname>, otherwise it just returns the generated
        random name (suffix for the Handle).

        :param prefix: Optional. The prefix to be used for the Handle name.
        :return: The handle name in the form <prefix>/<generatedsuffix> or
            <generatedsuffix>.
        '''

        LOGGER.debug('generate_PID_name...')

        randomuuid = uuid.uuid4()
        if prefix is not None:
            return prefix + '/' + str(randomuuid)
        else:
            return str(randomuuid)

    # Other public methods

    def get_handlerecord_indices_for_key(self, key, list_of_entries):
        '''
        Finds the Handle entry indices of all entries that have a specific
        type.

        *Important:* It finds the Handle System indices! These are not
        the python indices of the list, so they can not be used for
        iteration.

        :param key: The key (Handle Record type)
        :param list_of_entries: A list of the existing entries in which to find
            the indices.
        :return: A list of strings, the indices of the entries of type "key" in
            the given handle record.
        '''

        LOGGER.debug('get_handlerecord_indices_for_key...')

        indices = []
        for entry in list_of_entries:
            if entry['type'] == key:
                indices.append(entry['index'])
        return indices

    # Private methods:

    def __send_handle_delete_request(self, handle, indices=None, op=None):
        '''
        Send a HTTP DELETE request to the handle server to delete either an
            entire handle or to some specified values from a handle record,
            using the requests module.

        :param handle: The handle.
        :param indices: Optional. A list of indices to delete. Defaults to
            None (i.e. the entire handle is deleted.). The list can contain
            integers or strings.
        :return: The server's response.
        '''

        resp = self.__handlesystemconnector.send_handle_delete_request(
            handle=handle,
            indices=indices,
            op=op)
        return resp

    def __send_handle_put_request(self, handle, list_of_entries, indices=None, overwrite=False, op=None):
        '''
        Send a HTTP PUT request to the handle server to write either an entire
            handle or to some specified values to an handle record, using the
            requests module.

        :param handle: The handle.
        :param list_of_entries: A list of handle record entries to be written,
         in the format [{"index":xyz, "type":"xyz", "data":"xyz"}] or similar.
        :param indices: Optional. A list of indices to modify. Defaults
         to None (i.e. the entire handle is updated.). The list can
         contain integers or strings.
        :param overwrite: Optional. Whether the handle should be overwritten
         if it exists already.
        :return: The server's response.
        '''

        resp, payload = self.__handlesystemconnector.send_handle_put_request(
            handle=handle,
            list_of_entries=list_of_entries,
            indices=indices,
            overwrite=overwrite,
            op=op
        )
        return resp, payload

    def __send_handle_get_request(self, handle, indices=None):
        '''
        Send a HTTP GET request to the handle server to read either an entire
            handle or to some specified values from a handle record, using the
            requests module.

        :param handle: The handle.
        :param indices: Optional. A list of indices to delete. Defaults to
            None (i.e. the entire handle is deleted.). The list can contain
            integers or strings.
        :return: The server's response.
        '''

        resp = self.__handlesystemconnector.send_handle_get_request(handle, indices)
        return resp

    def __get_handle_record_if_necessary(self, handle, handlerecord_json):
        '''
        Returns the handle record if it is None or if its handle is not the
            same as the specified handle.

        '''
        if handlerecord_json is None:
            handlerecord_json = self.retrieve_handle_record_json(handle)
        else:
            if handle != handlerecord_json['handle']:
                handlerecord_json = self.retrieve_handle_record_json(handle)
        return handlerecord_json

    def __make_another_index(self, list_of_entries, url=False, hs_admin=False):
        '''
        Find an index not yet used in the handle record and not reserved for
            any (other) special type.

        :param: list_of_entries: List of all entries to find which indices are
            used already.
        :param url: If True, an index for an URL entry is returned (1, unless
            it is already in use).
        :param hs_admin: If True, an index for HS_ADMIN is returned (100 or one
            of the following).
        :return: An integer.
        '''

        start = 2

        # reserved indices:
        reserved_for_url = set([1])
        reserved_for_admin = set(range(100, 200))
        prohibited_indices = reserved_for_url | reserved_for_admin

        if url:
            prohibited_indices = prohibited_indices - reserved_for_url
            start = 1
        elif hs_admin:
            prohibited_indices = prohibited_indices - reserved_for_admin
            start = 100

        # existing indices
        existing_indices = set()
        if list_of_entries is not None:
            for entry in list_of_entries:
                existing_indices.add(int(entry['index']))

        # find new index:
        all_prohibited_indices = existing_indices | prohibited_indices
        searchmax = max(start, max(all_prohibited_indices)) + 2
        for index in xrange(start, searchmax):
            if index not in all_prohibited_indices:
                return index

    def __create_entry(self, entrytype, data, index, ttl=None):
        '''
        Create an entry of any type except HS_ADMIN.

        :param entrytype: THe type of entry to create, e.g. 'URL' or
            'checksum' or ... Note: For entries of type 'HS_ADMIN', please
            use __create_admin_entry(). For type '10320/LOC', please use
            'add_additional_URL()'
        :param data: The actual value for the entry. Can be a simple string,
            e.g. "example", or a dict {"format":"string", "value":"example"}.
        :param index: The integer to be used as index.
        :param ttl: Optional. If not set, the library's default is set. If
            there is no default, it is not set by this library, so Handle
            System sets it.
        :return: The entry as a dict.
        '''

        if entrytype == 'HS_ADMIN':
            op = 'creating HS_ADMIN entry'
            msg = 'This method can not create HS_ADMIN entries.'
            raise IllegalOperationException(operation=op, msg=msg)

        entry = {'index':index, 'type':entrytype, 'data':data}

        if ttl is not None:
            entry['ttl'] = ttl

        return entry

    def __create_admin_entry(self, handleowner, permissions, index, handle, ttl=None):
        '''
        Create an entry of type "HS_ADMIN".

        :param username: The username, i.e. a handle with an index
            (index:prefix/suffix). The value referenced by the index contains
            authentcation information, e.g. a hidden entry containing a key.
        :param permissions: The permissions as a string of zeros and ones,
            e.g. '0111011101011'. If not all twelve bits are set, the remaining
            ones are set to zero.
        :param index: The integer to be used as index of this admin entry (not
            of the username!). Should be 1xx.
        :param ttl: Optional. If not set, the library's default is set. If
            there is no default, it is not set by this library, so Handle
            System sets it.
        :return: The entry as a dict.
        '''
        # If the handle owner is specified, use it. Otherwise, use 200:0.NA/prefix
        # With the prefix taken from the handle that is being created, not from anywhere else.
        if handleowner is None:
            adminindex = '200'
            prefix = handle.split('/')[0]
            adminhandle = '0.NA/' + prefix
        else:
            adminindex, adminhandle = utilhandle.remove_index_from_handle(handleowner)

        data = {
            'value':{
                'index':adminindex,
                'handle':adminhandle,
                'permissions':permissions
            },
            'format':'admin'
        }

        entry = {'index':index, 'type':'HS_ADMIN', 'data':data}
        if ttl is not None:
            entry['ttl'] = ttl

        return entry

    def __get_python_indices_for_key(self, key, list_of_entries):
        '''
        Finds the indices of all entries that have a specific type. Important:
            This method finds the python indices of the list of entries! These
            are not the Handle System index values!

        :param key: The key (Handle Record type)
        :param list_of_entries: A list of the existing entries in which to find
            the indices.
        :return: A list of integers, the indices of the entries of type "key"
            in the given list.
        '''
        indices = []
        for i in xrange(len(list_of_entries)):
            if list_of_entries[i]['type'] == key:
                indices.append(i)
        return indices

    def __exchange_URL_in_13020loc(self, oldurl, newurl, list_of_entries, handle):
        '''
        Exchange every occurrence of oldurl against newurl in a 10320/LOC entry.
            This does not change the ids or other xml attributes of the
            <location> element.

        :param oldurl: The URL that will be overwritten.
        :param newurl: The URL to write into the entry.
        :param list_of_entries: A list of the existing entries (to find and
            remove the correct one).
        :param handle: Only for the exception message.
        :raise: GenericHandleError: If several 10320/LOC exist (unlikely).
        '''

        # Find existing 10320/LOC entries
        python_indices = self.__get_python_indices_for_key(
            '10320/LOC',
            list_of_entries
        )

        num_exchanged = 0
        if len(python_indices) > 0:

            if len(python_indices) > 1:
                msg = str(len(python_indices)) + ' entries of type "10320/LOC".'
                raise BrokenHandleRecordException(handle=handle, msg=msg)

            for index in python_indices:
                entry = list_of_entries.pop(index)
                xmlroot = ET.fromstring(entry['data']['value'])
                all_URL_elements = xmlroot.findall('location')
                for element in all_URL_elements:
                    if element.get('href') == oldurl:
                        LOGGER.debug('__exchange_URL_in_13020loc: Exchanging URL ' + oldurl + ' from 10320/LOC.')
                        num_exchanged += 1
                        element.set('href', newurl)
                entry['data']['value'] = ET.tostring(xmlroot, encoding=encoding_value)
                list_of_entries.append(entry)

        if num_exchanged == 0:
            LOGGER.debug('__exchange_URL_in_13020loc: No URLs exchanged.')
        else:
            message = '__exchange_URL_in_13020loc: The URL "' + oldurl + '" was exchanged ' + str(num_exchanged) + \
            ' times against the new url "' + newurl + '" in 10320/LOC.'
            message = message.replace('1 times', 'once')
            LOGGER.debug(message)

    def __remove_URL_from_10320LOC(self, url, list_of_entries, handle):
        '''
        Remove an URL from the handle record's "10320/LOC" entry.
        If it exists several times in the entry, all occurences are removed.
        If the URL is not present, nothing happens.
        If after removing, there is no more URLs in the entry, the entry is
            removed.

        :param url: The URL to be removed.
        :param list_of_entries: A list of the existing entries (to find and
            remove the correct one).
        :param handle: Only for the exception message.
        :raise: GenericHandleError: If several 10320/LOC exist (unlikely).
        '''

        # Find existing 10320/LOC entries
        python_indices = self.__get_python_indices_for_key(
            '10320/LOC',
            list_of_entries
        )

        num_removed = 0
        if len(python_indices) > 0:

            if len(python_indices) > 1:
                msg = str(len(python_indices)) + ' entries of type "10320/LOC".'
                raise BrokenHandleRecordException(handle=handle, msg=msg)

            for index in python_indices:
                entry = list_of_entries.pop(index)
                xmlroot = ET.fromstring(entry['data']['value'])
                all_URL_elements = xmlroot.findall('location')
                for element in all_URL_elements:
                    if element.get('href') == url:
                        LOGGER.debug('__remove_URL_from_10320LOC: Removing URL ' + url + '.')
                        num_removed += 1
                        xmlroot.remove(element)
                remaining_URL_elements = xmlroot.findall('location')
                if len(remaining_URL_elements) == 0:
                    LOGGER.debug("__remove_URL_from_10320LOC: All URLs removed.")
                    # TODO FIXME: If we start adapting the Handle Record by
                    # index (instead of overwriting the entire one), be careful
                    # to delete the ones that became empty!
                else:
                    entry['data']['value'] = ET.tostring(xmlroot, encoding=encoding_value)
                    LOGGER.debug('__remove_URL_from_10320LOC: ' + str(len(remaining_URL_elements)) + ' URLs' + \
                        ' left after removal operation.')
                    list_of_entries.append(entry)
        if num_removed == 0:
            LOGGER.debug('__remove_URL_from_10320LOC: No URLs removed.')
        else:
            message = '__remove_URL_from_10320LOC: The URL "' + url + '" was removed '\
            + str(num_removed) + ' times.'
            message = message.replace('1 times', 'once')
            LOGGER.debug(message)

    def __add_URL_to_10320LOC(self, url, list_of_entries, handle=None, weight=None, http_role=None, **kvpairs):
        '''
        Add a url to the handle record's "10320/LOC" entry.
            If no 10320/LOC entry exists, a new one is created (using the
            default "chooseby" attribute, if configured).
            If the URL is already present, it is not added again, but
            the attributes (e.g. weight) are updated/added.
            If the existing 10320/LOC entry is mal-formed, an exception will be
            thrown (xml.etree.ElementTree.ParseError)
            Note: In the unlikely case that several "10320/LOC" entries exist,
            an exception is raised.

        :param url: The URL to be added.
        :param list_of_entries: A list of the existing entries (to find and
            adapt the correct one).
        :param weight: Optional. The weight to be set (integer between 0 and
            1). If None, no weight attribute is set. If the value is outside
            the accepted range, it is set to 1.
        :param http_role: Optional. The http_role to be set. This accepts any
            string. Currently, Handle System can process 'conneg'. In future,
            it may be able to process 'no_conneg' and 'browser'.
        :param handle: Optional. Only for the exception message.
        :param all others: Optional. All other key-value pairs will be set to
            the element. Any value is accepted and transformed to string.
        :raise: GenericHandleError: If several 10320/LOC exist (unlikely).

        '''

        # Find existing 10320/LOC entry or create new
        indices = self.__get_python_indices_for_key('10320/LOC', list_of_entries)
        makenew = False
        entry = None
        if len(indices) == 0:
            index = self.__make_another_index(list_of_entries)
            entry = self.__create_entry('10320/LOC', 'add_later', index)
            makenew = True
        else:
            if len(indices) > 1:
                msg = 'There is ' + str(len(indices)) + ' 10320/LOC entries.'
                raise BrokenHandleRecordException(handle=handle, msg=msg)
            ind = indices[0]
            entry = list_of_entries.pop(ind)

        # Get xml data or make new:
        xmlroot = None
        if makenew:
            xmlroot = ET.Element('locations')
            if self.__10320LOC_chooseby is not None:
                xmlroot.set('chooseby', self.__10320LOC_chooseby)
        else:
            try:
                xmlroot = ET.fromstring(entry['data']['value'])
            except TypeError:
                xmlroot = ET.fromstring(entry['data'])
        LOGGER.debug("__add_URL_to_10320LOC: xmlroot is (1) " + ET.tostring(xmlroot, encoding=encoding_value))

        # Check if URL already there...
        location_element = None
        existing_location_ids = []
        if not makenew:
            list_of_locations = xmlroot.findall('location')
            for item in list_of_locations:
                try:
                    existing_location_ids.append(int(item.get('id')))
                except TypeError:
                    pass
                if item.get('href') == url:
                    location_element = item
            existing_location_ids.sort()
        # ... if not, add it!
        if location_element is None:
            location_id = 0
            for existing_id in existing_location_ids:
                if location_id == existing_id:
                    location_id += 1
            location_element = ET.SubElement(xmlroot, 'location')
            LOGGER.debug("__add_URL_to_10320LOC: location_element is (1) " + ET.tostring(location_element, encoding=encoding_value) + ', now add id ' + str(location_id))
            location_element.set('id', str(location_id))
            LOGGER.debug("__add_URL_to_10320LOC: location_element is (2) " + ET.tostring(location_element, encoding=encoding_value) + ', now add url ' + str(url))
            location_element.set('href', url)
            LOGGER.debug("__add_URL_to_10320LOC: location_element is (3) " + ET.tostring(location_element, encoding=encoding_value))
            self.__set_or_adapt_10320LOC_attributes(location_element, weight, http_role, **kvpairs)
        # FIXME: If we start adapting the Handle Record by index (instead of
        # overwriting the entire one), be careful to add and/or overwrite!

        # (Re-)Add entire 10320 to entry, add entry to list of entries:
        LOGGER.debug("__add_URL_to_10320LOC: xmlroot is (2) " + ET.tostring(xmlroot, encoding=encoding_value))
        entry['data'] = ET.tostring(xmlroot, encoding=encoding_value)
        list_of_entries.append(entry)

    def __set_or_adapt_10320LOC_attributes(self, locelement, weight=None, http_role=None, **kvpairs):
        '''
        Adds or updates attributes of a <location> element. Existing attributes
            are not removed!

        :param locelement: A location element as xml snippet
            (xml.etree.ElementTree.Element).
        :param weight: Optional. The weight to be set (integer between 0 and
            1). If None, no weight attribute is set. If the value is outside
            the accepted range, it is set to 1.
        :param http_role: Optional. The http_role to be set. This accepts any
            string. Currently, Handle System can process 'conneg'. In future,
            it may be able to process 'no_conneg' and 'browser'.
        :param all others: Optional. All other key-value pairs will be set to
            the element. Any value is accepted and transformed to string.
        '''

        if weight is not None:
            LOGGER.debug('__set_or_adapt_10320LOC_attributes: weight (' + str(type(weight)) + '): ' + str(weight))
            weight = float(weight)
            if weight < 0  or weight > 1:
                default = 1
                LOGGER.debug('__set_or_adapt_10320LOC_attributes: Invalid weight (' + str(weight) + \
                    '), using default value (' + str(default) + ') instead.')
                weight = default
            weight = str(weight)
            locelement.set('weight', weight)

        if http_role is not None:
            locelement.set('http_role', http_role)

        for key, value in kvpairs.items():
            locelement.set(key, str(value))

    def __log_request_response_to_file(self, **args):
        message = util.make_request_log_message(**args)
        args['logger'].info(message)
