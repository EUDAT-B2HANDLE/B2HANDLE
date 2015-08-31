'''
Created on 2015-07-02
Started implementing 2015-07-15
Last updates 2015-08-26
'''

# pylint handleclient_cont.py --method-rgx="[a-z_][a-zA-Z0-9_]{2,30}$" --max-line-length=250 --variable-rgx="[a-z_][a-zA-Z0-9_]{2,30}$" --attr-rgx="[a-z_][a-zA-Z0-9_]{2,30}$" --argument-rgx="[a-z_][a-zA-Z0-9_]{2,30}$"

import b2handle.handleexceptions
import b2handle.clientcredentials
import requests
import urllib
import json
import copy
import xml.etree.ElementTree as ET
import base64
import uuid
import logging
import re

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

class EUDATHandleClient(object):
    '''
    B2Handle main client class.
    (formerly B2SAFE epic client)
    '''

    # Instantiation:

    def __init__(self, handle_server_url=None, **args):
        '''
        Initialize the client in read-only mode. Access is anonymous,
            thus no credentials are required.
            Note: With read-only access, searching for handles is not possible.

        :param handle_server_url: Optional. The URL of the Handle System
            server to read from. Defaults to 'https://hdl.handle.net'
        :param username: This must be a handle value reference in the format
            "index:prefix/suffix". The method will throw an exception upon bad
            syntax or non-existing Handle. The existence or validity of the
            password in the handle is not checked at this moment.
        :param password: This is the password stored as secret key in the
            actual Handle value the username points to.

        :param REST_API_url_extension: Optional. The extension of a Handle
            Server's URL to access its REST API. Defaults to '/api/handles/'.
        :param allowed_search_keys: Optional. The keys that can be used for
            reverse lookup of handles, as a list of strings. Defaults to 'url'
            and 'checksum'. If the list is empty, all keys are passed to the
            reverse lookup servlet and exceptions are passed on to the user.
        :param __10320loc_chooseby: Optional. The value to give to a handle
            record's 10320/loc entry's 'chooseby' attribute as string (e.g.
            'locatt,weighted'). Defaults to None (attribute not set).
        :param modify_HS_ADMIN: Optional. Determines whether the HS_ADMIN
            handle record entry can be modified using this library. Defaults to
            False.
        :param HTTP_verify: Optional. If set to False, the certificate is not
            verified in HTTP requests. Defaults to True.
        :param reverselookup_baseuri: Optional. The base URL of the reverse
            lookup service. If not set, the handle server base URL is used.
        :param reverselookup_url_extension: Optional. The path to append to
            the reverse lookup base URL to reach the reverse lookup service.
            Defaults to '/hrls/handles/'
        '''

        # All used attributes (some will be overwritten below)
        self.__username = None
        self.__password = None
        self.__handle_server_url = 'https://hdl.handle.net'
        self.__default_permissions = '011111110011' # default from hdl-admintool
        self.__can_modify_HS_ADMIN = False
        self.__10320loc_chooseby = None
        self.__handle_server_url = 'https://hdl.handle.net'
        self.__url_extension_REST_API = '/api/handles/'
        self.__http_verify = True
        self.__allowed_search_keys = ['url', 'checksum']
        self.__solrbaseurl = None
        self.__solrurlpath = '/hrls/handles/'
        self.__revlookup_auth_string = None
        self.__HS_auth_string = None
        LOGGER.debug('"__init__()": Passed keys: '+', '.join(args.keys()))


        # Needed for read and or write access:

        if handle_server_url is not None:
            LOGGER.debug('Handle server URL set to '+handle_server_url)
            self.__handle_server_url = handle_server_url
            self.__solrbaseurl = handle_server_url

        if 'REST_API_url_extension' in args.keys():
            self.__url_extension_REST_API = args['REST_API_url_extension']

        if 'HTTP_verify' in args.keys():
            LOGGER.info('"__init__(): Setting __http_verify to: '+\
                str(args['HTTP_verify']))
            self.__http_verify = self.string_to_bool(args['HTTP_verify'])

        # Needed for write access:

        if 'HS_ADMIN_permissions' in args.keys():
            self.__default_permissions = args['HS_ADMIN_permissions']

        if '10320loc_chooseby' in args.keys():
            self.__10320loc_chooseby = args['10320loc_chooseby']

        if 'modify_HS_ADMIN' in args.keys():
            self.__can_modify_HS_ADMIN = args['modify_HS_ADMIN']

        # For write access, username AND pw AND server url must be given!

        if 'username' in args.keys():
            if 'password' not in args.keys():
                raise TypeError('No password given.')
        if 'password' in args.keys():
            if 'username' not in args.keys():
                raise TypeError('No username given.')
        writeaccess = False
        if 'username' in args.keys() or 'password' in args.keys():
            writeaccess = True
            if handle_server_url is None:
                raise TypeError('No handle_server_URL given.')

        if writeaccess:
            self.check_handle_syntax_with_index(args['username'])
            self.check_if_username_exists(args['username'])
            self.__password = args['password']
            self.__username = args['username']
            LOGGER.debug('__init__(): Username set to: '+str(self.__username))
            LOGGER.debug('__init__(): Password set to: '+str(self.__password))
            self.__set_HS_auth_string(self.__username, self.__password)


        # Needed for reverse lookup:

        if 'allowed_search_keys' in args.keys():
            self.__allowed_search_keys = args['allowed_search_keys']

        if 'reverselookup_baseuri' in args.keys():
            self.__solrbaseurl = args['reverselookup_baseuri']

        if 'reverselookup_url_extension' in args.keys():
            self.__solrurlpath = args['reverselookup_url_extension']

        # Authentication reverse lookup:
        #   If specified, use it.
        #   Else: Try using handle system authentication
        #   Else: search_handle does not work and will raise an exception.

        revlookup_user = None
        if 'reverselookup_username' in args.keys():
            revlookup_user = args['reverselookup_username']
        elif self.__username is not None:
            revlookup_user = self.__username

        revlookup_pw = None
        if 'reverselookup_password' in args.keys():
            revlookup_pw = args['reverselookup_password']
        elif self.__password is not None:
            revlookup_pw = self.__password

        if revlookup_user is not None and revlookup_pw is not None:
            self.__set_revlookup_auth_string(revlookup_user, revlookup_pw)

    @staticmethod
    def instantiate_for_read_access(handle_server_url=None, **config):
        '''
        Initialize the client in read-only mode. Access is anonymous,
         thus no credentials are required.

        :param handle_server_url: Optional. The URL of the Handle System
            server to read from. Defaults to 'https://hdl.handle.net'
        :param **config: More key-value pairs may be passed that will be passed
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
        :param **config: More key-value pairs may be passed that will be passed
            on to the constructor as config. Config options from the
            credentials object are overwritten by this.
        :return: An instance of the client.
        '''

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
        :param **config: More key-value pairs may be passed that will be passed
            on to the constructor as config.
        :raises: HandleNotFoundException: If the username handle is not found.
        :raises: HandleSyntaxError
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
        :param **config: More key-value pairs may be passed that will be passed
            on to the constructor as config. Config options from the
            credentials object are overwritten by this.
        :raises: HandleNotFoundException: If the username handle is not found.
        :return: An instance of the client.
        '''
        user = credentials.get_username()
        pw = credentials.get_password()
        additional_config = credentials.get_config()

        if additional_config is not None:
            additional_config.update(**config)
        else:
            additional_config = config
        inst = EUDATHandleClient(
            credentials.get_server_URL(),
            username=user,
            password=pw,
            **additional_config
        )
        return inst

    # Methods with read access to Handle Server:

    def retrieve_handle_record_json(self, handle):
        '''
        Retrieve a handle record from the Handle server as a complete nested
            dict (including index, ttl, timestamp, ...) for later use.
        Note: For retrieving a simple dict with only the keys and values,
            please use "retrieve_handle_record()".

        :param handle whose record to retrieve.
        :return: The handle record as a nested dict. If the handle does not
            exist, returns None.
        '''

        self.check_handle_syntax(handle)
        response = self.__send_handle_get_request(handle)
        if self.handle_not_found(response):
            return None
        elif self.does_handle_exist(response):
            handlerecord_json = json.loads(response.content)
            return handlerecord_json
        elif self.is_handle_empty(response):
            handlerecord_json = json.loads(response.content)
            return handlerecord_json
        else:
            raise b2handle.handleexceptions.GenericHandleError(
                'retrieving', handle, response)

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
        :raises: HandleSyntaxError.
        '''

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            return None # Instead of HandleNotFoundException!
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
        :raises: HandleSyntaxError.
        :raises: HandleNotFoundException.
        '''

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            raise b2handle.handleexceptions.HandleNotFoundException(handle)
        list_of_entries = handlerecord_json['values']

        indices = []
        for i in xrange(len(list_of_entries)):
            if list_of_entries[i]['type'] == key:
                indices.append(i)

        if len(indices) == 0:
            return None
        else:
            if len(indices) > 1:
                LOGGER.info('The handle '+handle+' contains several entries\
                 of type "'+key+'". Only the first one is returned.')
            return list_of_entries[indices[0]]['data']['value']

    def is_10320loc_empty(self, handle, handlerecord_json=None):
        '''
        Checks if there is a 10320/loc entry in the handle record.
        Note: In the unlikely case that there is a 10320/loc entry, but it does
            not contain any locations, it is treated as if there was none.
            # TODO QUESTION to Robert: Is this the desired behaviour?

        :param handle: The handle.
        :param handlerecord_json: Optional. The content of the response of a
            GET request for the handle as a dict. Avoids another GET request.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :return: True if the record contains NO 10320/loc entry; False if it
            does contain one.
        '''

        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            raise b2handle.handleexceptions.HandleNotFoundException(handle)
        list_of_entries = handlerecord_json['values']

        num_entries = 0
        num_URL = 0
        for entry in list_of_entries:
            if entry['type'] == '10320/loc':
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

    def is_URL_contained_in_10320loc(self, handle, url, handlerecord_json=None):
        '''
        Checks if the URL is already present in the handle record's
            10320/loc entry.

        :param handle: The handle.
        :param url: The URL.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :return: True if the handle record's 10320/loc entry contains the URL;
            False otherwise. If the entry is empty or does not exist, False
            is returned.
        '''
        handlerecord_json = self.__get_handle_record_if_necessary(handle, handlerecord_json)
        if handlerecord_json is None:
            raise b2handle.handleexceptions.HandleNotFoundException(handle)
        list_of_entries = handlerecord_json['values']

        num_entries = 0
        num_URL = 0
        for entry in list_of_entries:
            if entry['type'] == '10320/loc':
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
            added to the handle record as 10320/loc entry.
        :raises: HandleAuthentificationError.
        :return: The new handle name.
        '''
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

        Note: We assume that a key exists only once. In case a key exists
            several time, an exception will be raised.
        Note: To modify 10320/loc, please use "add_additional_URL()" or
            "remove_additional_URL()".

        Parameters:
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
        :raises: HandleAuthentificationError.
        :raises: HandleNotFoundException.
        :raises: HandleSyntaxError.
        '''

        # Read handle record:
        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot modify unexisting handle'
            raise b2handle.handleexceptions.HandleNotFoundException(handle, msg)
        list_of_entries = handlerecord_json['values']

        # HS_ADMIN and 10320/loc:
        if 'HS_ADMIN' in kvpairs.keys() and not self.__can_modify_HS_ADMIN:
            msg = 'You may not modify HS_ADMIN'
            raise b2handle.handleexceptions.IllegalOperationException(
                msg, 'modifying HS_ADMIN', handle)

        if '10320/loc' in kvpairs.keys():
            msg = 'For modifying 10320/loc entries, please use the'+\
                ' methods "add_additional_URL" or "remove_additional_URL".'
            raise b2handle.handleexceptions.IllegalOperationException(
                msg, 'modifying 10320/loc', handle)

        nothingchanged = True
        new_list_of_entries = []
        keys = kvpairs.keys()
        for key, newval in kvpairs.iteritems():
            # Change existing entry:
            changed = False
            for i in xrange(len(list_of_entries)):
                if list_of_entries[i]['type'] == key:
                    if not changed:
                        list_of_entries[i]['data'] = newval
                        if key == 'HS_ADMIN':
                            newval['permissions'] = self.__default_permissions
                            list_of_entries[i]['data'] = {
                                'format':'admin',
                                'value':newval
                            }
                            LOGGER.info('modify_handle_value: Modified'+\
                                ' "HS_ADMIN" of handle '+handle)
                        changed = True
                        nothingchanged = False
                        new_list_of_entries.append(list_of_entries[i])
                    else:
                        msg = 'There is several entries of type "'+key+'".'+\
                            ' This can lead to unexpected behaviour.'+\
                            ' Please clean up before modifying the record.'
                        raise b2handle.handleexceptions.BrokenHandleRecordException(handle, msg)

            # If the entry doesn't exist yet, add it:
            if not changed:
                if add_if_not_exist:
                    LOGGER.info('modify_handle_value: Adding entry "'+key+'"'+\
                        ' to handle '+handle)
                    index = self.__make_another_index(list_of_entries)
                    entry_to_add = self.__create_entry(key, newval, index, ttl)
                    new_list_of_entries.append(entry_to_add)
                    changed = True
                    nothingchanged = False

        # Add the unchanged values
        for i in xrange(len(list_of_entries)):
            if list_of_entries[i]['type'] not in keys:
                new_list_of_entries.append(list_of_entries[i])

        # Overwrite the old record:
        if nothingchanged:
            LOGGER.info('modify_handle_value: There was no entries '+\
                str(kvpairs.keys())+' to be modified (handle '+handle+').'+\
                ' To add them, set add_if_not_exist = True')
        else:
            # TODO FIXME: Implement overwriting by index (less risky),
            # once HS have fixed the issue with the indices.
            resp = self.__send_handle_put_request(
                handle,
                new_list_of_entries,
                overwrite=True)
            if self.handle_success(resp):
                pass
            elif self.not_authenticated(resp):
                op = 'modifying handle values'
                raise b2handle.handleexceptions.HandleAuthentificationError(op, handle, resp)
            else:
                op = 'modifying handle values'
                msg = 'Values: '+str(kvpairs)
                raise b2handle.handleexceptions.GenericHandleError(op, handle, resp, msg)

    def delete_handle_value(self, handle, key):
        '''
        Delete a key-value pair from a handle record. If the key exists more
            than once, all key-value pairs with this key are deleted.

        :param handle: Handle from whose record the entry should be deleted.
        :param key: Key to be deleted. Also accepts a list of keys.
        :raises: HandleAuthentificationError.
        :raises: HandleNotFoundException.
        :raises: HandleSyntaxError.
        '''

        # read handle record:
        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot modify unexisting handle'
            raise b2handle.handleexceptions.HandleNotFoundException(handle, msg)
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
                raise b2handle.handleexceptions.IllegalOperationException(op, handle)

            if key not in keys_done:
                indices_onekey = self.get_handlerecord_indices_for_key(key, list_of_entries)
                indices = indices+indices_onekey
                keys_done.append(key)

        # delete and process response:
        resp = self.__send_handle_delete_request(handle, indices)
        if self.handle_success(resp):
            pass
        elif self.values_not_found(resp):
            pass
        elif self.not_authenticated(resp):
            op = 'deleting "'+str(key)+'"'
            raise b2handle.handleexceptions.HandleAuthentificationError(op, handle, resp)
        else:
            op = 'deleting "'+str(keys)+'"'
            raise b2handle.handleexceptions.GenericHandleError(op, handle, resp)

    def delete_handle(self, handle, *other):
        '''Delete the handle and its handle record.

        :param handle: Handle to be deleted.
        :param other: Deprecated. This only exists to catch wrong method usage
            by users who are used to delete handle VALUES with the method.
        :raises: HandleAuthentificationError.
        :raises: HandleNotFoundException.
        :raises: HandleSyntaxError.
        '''
        EUDATHandleClient.check_handle_syntax(handle)

        # Safety check. In old epic client, the method could be used for
        # deleting handle values (not entire handle) by specifying more
        # parameters.
        if len(other) > 0:
            message = 'You specified more than one argument. If you wanted'+\
                ' to delete just some values from a handle, please use the'+\
                ' new method "delete_handle_value()".'
            print message
            raise TypeError(message)

        resp = self.__send_handle_delete_request(handle)
        if self.handle_success(resp):
            LOGGER.info('delete_handle: Handle '+handle+' deleted.')
        elif self.handle_not_found(resp):
            message = 'delete_handle: Handle '+handle+' did not exist, so'+\
                ' it could not be deleted.'
            LOGGER.info(message)
        else:
            op = 'deleting handle'
            raise b2handle.handleexceptions.GenericHandleError(op, handle, resp)

    def add_additional_URL(self, handle, *urls, **attributes):
        '''
        Add a URL entry to the handle record's 10320/loc entry. If 10320/loc
            does not exist yet, it is created. If the 10320/loc entry already
            contains the URL, it is not added a second time.

        :param handle: The handle to add the URL to.
        :param urls: The URL(s) to be added. Several URLs may be specified.
        :param attributes: Optional. Additional key-value pairs to set as
            attributes to the <location> elements, e.g. weight, http_role or
            custom attributes. Note: If the URL already exists but the
            attributes are different, they are updated!
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :raises: HandleAuthentificationError
        '''

        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot add URLS to unexisting handle!'
            raise b2handle.handleexceptions.HandleNotFoundException(handle, msg)
        list_of_entries = handlerecord_json['values']

        for url in urls:
            self.__add_URL_to_10320loc(url, list_of_entries, handle)

        resp = self.__send_handle_put_request(handle, list_of_entries, overwrite=True)
        # TODO FIXME (one day) Overwrite by index.

        if self.handle_success(resp):
            pass
        elif self.not_authenticated(resp):
            msg = 'Could not add URLs '+str(urls)
            op = 'adding URLs'
            raise b2handle.handleexceptions.HandleAuthentificationError(op, handle, resp)
        else:
            op = 'adding "'+str(urls)+'"'
            raise b2handle.handleexceptions.GenericHandleError(op, handle, resp)

    def remove_additional_URL(self, handle, *urls):
        '''
        Remove a URL from the handle record's 10320/loc entry.

        :param handle: The handle to modify.
        :param urls: The URL(s) to be removed. Several URLs may be specified.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :raises: HandleAuthentificationError
        '''

        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is None:
            msg = 'Cannot remove URLs from unexisting handle'
            raise b2handle.handleexceptions.HandleNotFoundException(handle, msg, resp)
        list_of_entries = handlerecord_json['values']

        for url in urls:
            self.__remove_URL_from_10320loc(url, list_of_entries, handle)


        resp = self.__send_handle_put_request(
            handle,
            list_of_entries,
            overwrite=True
        )
        # TODO FIXME (one day): Implement overwriting by index (less risky),
        # once HS have fixed the issue with the indices.
        if self.handle_success(resp):
            pass
        elif self.not_authenticated(resp):
            msg = 'Could not remove URLs '+str(urls)
            op = 'removing URLs'
            raise b2handle.handleexceptions.HandleAuthentificationError(op, handle, resp)
        else:
            op = 'removing "'+str(urls)+'"'
            raise b2handle.handleexceptions.GenericHandleError(op, handle, resp)

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
            added to the handle record as 10320/loc entry.
        :param overwrite: Optional. If set to True, an existing handle record
            will be overwritten. Defaults to False.
        :raises: HandleAlreadyExistsException. Only if overwrite is not set or
            set to False.
        :raises: HandleAuthentificationError.
        :raises: HandleSyntaxError.
        :return: The handle name.
        '''
        LOGGER.debug('"register_handle()" for handle '+handle+'.')

        # If already exists and can't be overwritten:
        handlerecord_json = self.retrieve_handle_record_json(handle)
        if handlerecord_json is not None and overwrite == False:
            msg = 'Could not register handle'
            raise b2handle.handleexceptions.HandleAlreadyExistsException(handle, msg)

        # Create admin entry
        list_of_entries = []
        if not self.__username:
            op = 'creating handle without username'
            msg = 'No username specified. Can not create handle without'+\
                ' username. Please instantiate the client with a username'
            raise b2handle.handleexceptions.IllegalOperationException(op, handle, msg)
        adminentry = self.__create_admin_entry(
            self.__username,
            self.__default_permissions,
            self.__make_another_index(list_of_entries, hs_admin=True)
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
                'checksum',
                checksum,
                self.__make_another_index(list_of_entries)
            )
            list_of_entries.append(entryChecksum)
        if extratypes is not None:
            for key, value in extratypes.iteritems():
                entry = self.__create_entry(
                    key,
                    value,
                    self.__make_another_index(list_of_entries)
                )
                list_of_entries.append(entry)
        if additional_URLs is not None and len(additional_URLs) > 0:
            for url in additional_URLs:
                self.__add_URL_to_10320loc(url, list_of_entries, handle)

        # Create record itself and put to server
        resp = self.__send_handle_put_request(
            handle,
            list_of_entries,
            overwrite=overwrite
        )

        if self.was_handle_created(resp) or self.handle_success(resp):
            return json.loads(resp.content)['handle']
        else:
            if self.not_authenticated(resp):
                op = 'registering handle'
                raise b2handle.handleexceptions.HandleAuthentificationError(op, handle)
            else:
                op = 'registering handle'
                raise b2handle.handleexceptions.GenericHandleError(op, handle, resp)

    # No HS access:

    def search_handle(self, url=None, prefix=None, **key_value_pairs):
        '''
        Search for handles containing the specified key with the specified
            value. The search terms are passed on to the reverse lookup servlet
            as-is. The servlet is supposed to be case-insensitive, but if it
            isn't, the wrong case will cause a ReverseLookupException.
        Note: If allowed search keys are configured, only these are used. If
            no allowed search keys are specified, all key-value pairs are
            passed on to the reverse lookup servlet, possibly causing a
            ReverseLookupException.

        Example calls:
        list_of_handles = search_handle('http://www.foo.com')
        list_of_handles = search_handle('http://www.foo.com', checksum=99999)
        list_of_handles = search_handle(url='http://www.foo.com', checksum=99999)

        :param url: Optional. The URL to search for (reverse lookup). [This is
            NOT the URL of the search servlet!]
        :param prefix: Optional. The Handle prefix to which the search should
            be limited to. If unspecified, the method will search across all
            prefixes present at the server given to the constructor.
        :param key_value_pairs: Optional. Several search fields and values can
            be specified as key-value-pairs,
            e.g. checksum=123456, url=www.foo.com
        :raise: ReverseLookupException: If a search field is specified that
            can not be used, or if something else goes wrong.
        :return: A list of all Handles (strings) that bear the given key with
            given value of given prefix or server. The list may be empty and
            may also contain more than one element.
        '''

        if url is None and len(key_value_pairs) == 0:
            LOGGER.info('search_handle: No key value pair was specified.')
            msg = 'Please specify at least one key-value pair to search for.'
            raise TypeError(msg)

        kvpairs = copy.deepcopy(key_value_pairs)
        if url is not None:
            kvpairs['url'] = url

        if url is None and 'URL' in key_value_pairs.keys():
            val = kvpairs['URL']
            kvpairs['url'] = val
            del kvpairs['URL']

        list_of_handles = []
        LOGGER.debug('search_handle: key-value-pairs: '+str(kvpairs))
        query = self.create_revlookup_query(**kvpairs)

        if query is None:
            msg = 'No search query was specified'
            raise b2handle.handleexceptions.ReverseLookupException(msg)

        resp = self.__send_revlookup_get_request(query)

        # Check for undefined fields
        rx = 'RemoteSolrException: Error from server at .+: undefined field .+'
        match = re.compile(rx).search(resp.content)
        if match is not None:
            undefined_field = resp.content.split('undefined field ')[1]
            msg = 'Tried to search in undefined field "'+undefined_field+'"..'
            raise b2handle.handleexceptions.ReverseLookupException(msg, query, resp)

        if resp.status_code == 200:
            list_of_handles = json.loads(resp.content)
        elif resp.status_code == 401:
            msg = 'Authentication failed.'
            if self.__username is not None:
                msg += (' If the Reverse Lookup Servlet you are'
                    ' using does not accept the same username and password'
                    ' as the Handle Server, please provide its username and'
                    ' password separately when instantiating the client')
            else:
                msg +=' You need to specify a username and password to search'
            raise b2handle.handleexceptions.ReverseLookupException(msg, query, resp)
        elif resp.status_code == 404:
            msg = 'Wrong search servlet URL ('+resp.request.url+')'
            rx = 'The handle you requested.+cannot be found'
            match = re.compile(rx, re.DOTALL).search(resp.content)
            if match is not None:
                msg += '. It seems you reached a Handle Server'
            raise b2handle.handleexceptions.ReverseLookupException(msg, query, resp)

        else:
            raise b2handle.handleexceptions.ReverseLookupException(None, query, resp)

        # Filter prefixes:
        # TODO QUESTION to Robert: Is this the desired behaviour?
        if prefix is not None:
            LOGGER.debug('Restricting search to prefix '+prefix)
            filteredlist_of_handles = []
            for i in xrange(len(list_of_handles)):
                if list_of_handles[i].split('/')[0] == prefix:
                    filteredlist_of_handles.append(list_of_handles[i])
            list_of_handles = filteredlist_of_handles

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
        randomuuid = uuid.uuid4()
        if prefix is not None:
            return prefix+'/'+str(randomuuid)
        else:
            return str(randomuuid)

    # Other public methods

    def make_handle_URL(self, handle, indices=None, overwrite=None, other_url=None):
        '''
        Create the URL for a HTTP request (URL + query string) to request
         a specific handle from the Handle Server.

        :param handle: The handle to access.
        :param indices: Optional. A list of integers or strings. Indices of
            the handle record entries to read or write. Defaults to None.
        :param overwrite: Optional. If set, an overwrite flag will be appended
            to the URL (?overwrite=true or ?overwrite=false). If not set, no
            flag is set, thus the Handle Server's default behaviour will be
            used. Defaults to None.
        :param other_url: Optional. If a different Handle Server URL than the
            one specified in the constructor should be used. Defaults to None.
            If set, it should be set including the URL extension,
            e.g. '/api/handles/'.
        :return: The complete URL, e.g.
         'http://some.handle.server/api/handles/prefix/suffix?index=2&index=6&overwrite=false
        '''

        if other_url is not None:
            url = other_url
        else:
            LOGGER.debug('"make_handle_value()": Server URL: '+\
                str(self.__handle_server_url))
            LOGGER.debug('"make_handle_value()": path to REST API: '+\
                str(self.__url_extension_REST_API))
            url = self.__handle_server_url.strip('/') +'/'+\
                self.__url_extension_REST_API.strip('/')
        url = url.strip('/')+'/'+ handle

        if indices is None:
            indices = []
        if len(indices) > 0:
            url = url+'?'
            for index in indices:
                url = url+'&index='+str(index)

        if overwrite is not None:
            if overwrite:
                url = url+'?&overwrite=true'
            else:
                url = url+'?&overwrite=false'

        url = url.replace('?&', '?')
        return url

    @staticmethod
    def check_handle_syntax(string):
        '''
        Checks the syntax of a handle without an index (are prefix and suffix
            there, are there too many slashes).

        :string: The handle without index, as string prefix/suffix.
        :raise: HandleSyntaxError
        :return: True. If it's not ok, exceptions are raised.

        '''
        arr = string.split('/')

        if len(arr) > 2:
            msg = 'Too many slashes'
            expected = 'prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)
        elif len(arr) < 2:
            msg = 'No slash'
            expected = 'prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)

        if len(arr[0]) == 0:
            msg = 'Empty prefix'
            expected = 'prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)

        if len(arr[1]) == 0:
            msg = 'Empty suffix'
            expected = 'prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)

        return True

    @staticmethod
    def check_handle_syntax_with_index(string):
        '''
        Checks the syntax of a handle with an index (is index there, is it an
            integer), and of the handle itself.
        :string: The handle with index, as string index:prefix/suffix.
        :raise: HandleSyntaxError
        :return: True. If it's not ok, exceptions are raised.
        '''

        arr = string.split(':')
        if len(arr) > 2:
            msg = 'Too many colons'
            expected = 'index:prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)
        elif len(arr) < 2:
            msg = 'No colon'
            expected = 'index:prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)
        try:
            int(arr[0])
        except ValueError:
            msg = 'Index is not an integer'
            expected = 'index:prefix/suffix'
            raise b2handle.handleexceptions.HandleSyntaxError(msg, string, expected)

        EUDATHandleClient.check_handle_syntax(string)
        return True

    @staticmethod
    def remove_index(handle_with_index):
        '''
        Returns index and handle separately, in a tuple.

        :param handle_with_index: THe handle string with an index (e.g.
            500:prefix/suffix)
        :return: index and handle as a tuple.
        '''
        if len(handle_with_index.split(':')) > 1:
            return handle_with_index.split(':')

    def get_handlerecord_indices_for_key(self, key, list_of_entries):
        '''
        Finds the Handle entry indices of all entries that have a specific
            type. Important: It finds the Handle System indices! These are not
            the python indices of the list, so they can not be used for
            iteration.

        :param key: The key (Handle Record type)
        :param list_of_entries: A list of the existing entries in which to find
            the indices.
        :return: A list of strings, the indices of the entries of type "key" in
            the given handle record.
        '''
        indices = []
        for entry in list_of_entries:
            if entry['type'] == key:
                indices.append(entry['index'])
        return indices

    @staticmethod
    def create_authentication_string(username, password):
        '''
        Create an authentication string from the username and password.

        :param username: Username.
        :param password: Password.
        :return: The encoded string.
        '''
        username_utf8 = username.encode('utf-8')
        userpw_utf8 = password.encode('utf-8')
        username_perc = urllib.quote(username_utf8)
        userpw_perc = urllib.quote(userpw_utf8)

        authinfostring = username_perc + ':' + userpw_perc
        authinfostring_base64 = base64.b64encode(authinfostring)
        return authinfostring_base64

    def check_if_username_exists(self, username):
        '''
        Check if the username handles exists.

        :param username: The username, in the form index:prefix/suffix
        :raises: HandleNotFoundException
        :raises: GenericHandleError
        :return: True. If it does not exist, an exception is raised.

        Note: Only the existence of the handle is verified. The existence or
            validity of the index is not checked, because entries containing
            a key are hidden anyway.

        '''
        _, handle = self.remove_index(username)

        resp = self.__send_handle_get_request(handle)
        if self.does_handle_exist(resp):
            return True
        elif self.handle_not_found(resp):
            msg = 'The username handle does not exist'
            raise b2handle.handleexceptions.HandleNotFoundException(handle, msg, resp)
        else:
            op = 'checking if handle exists'
            msg = 'Checking if username exists went wrong'
            raise b2handle.handleexceptions.GenericHandleError(op, handle, resp, msg)

    def create_revlookup_query(self, *fulltext_searchterms, **keyvalue_searchterms):
        '''
        Create the part of the solr request that comes after the question mark,
            e.g. ?url=*dkrz*&checksum=*abc*. If allowed search keys are
            configured, only these are used. If no'allowed search keys are
            specified, all key-value pairs are passed on to the reverse lookup
            servlet.

        :param fulltext_searchterms: Optional. Any term specified will be used
            as search term. Not implemented yet, so will be ignored.
        :param keyvalue_searchterms: Optional. Key-value pairs. Any key-value
            pair will be used to search for the value in the field "key".
            Wildcards accepted (refer to the documentation of the reverse
            lookup servlet for syntax.)
        :return: The query string, after the "?". If no valid search terms were
            specified, None is returned.
        '''

        allowed_search_keys = self.__allowed_search_keys
        only_search_for_allowed_keys = False
        if len(allowed_search_keys) > 0:
            only_search_for_allowed_keys = True

        fulltext_searchterms_given = True
        if len(fulltext_searchterms) == 0:
            fulltext_searchterms_given = False
        if len(fulltext_searchterms) == 1 and fulltext_searchterms[0] is None:
            fulltext_searchterms_given = False
        if fulltext_searchterms_given:
            msg = 'Full-text search is not implemented yet.'+\
                ' The provided searchterms '+str(fulltext_searchterms)+\
                ' can not be used.'
            raise b2handle.handleexceptions.ReverseLookupException(msg)

        keyvalue_searchterms_given = True
        if len(keyvalue_searchterms) == 0:
            keyvalue_searchterms_given = False
        if len(keyvalue_searchterms) == 1 and\
            keyvalue_searchterms.itervalues().next() is None:
            keyvalue_searchterms_given = False

        if not keyvalue_searchterms_given and not fulltext_searchterms_given:
            msg = 'No search terms have been specified. Please specify'+\
                ' at least one key-value-pair.'
            raise b2handle.handleexceptions.ReverseLookupException(msg)

        counter = 0
        query = '?'
        for key, value in keyvalue_searchterms.iteritems():

            if only_search_for_allowed_keys and key not in allowed_search_keys:
                msg = 'Cannot search for key "'+key+'". Only searches'+\
                    'for keys '+str(allowed_search_keys)+' are implemented.'
                raise b2handle.handleexceptions.ReverseLookupException(msg)
            else:
                query = query+'&'+key+'='+value
                counter += 1

        query = query.replace('?&', '?')
        LOGGER.debug('create_revlookup_query: query: '+query)
        if counter == 0:
            msg = 'No valid search terms have been specified.'
            raise b2handle.handleexceptions.ReverseLookupException(msg)
        return query

    # Handling responses (TODO improve):

    def handle_success(self, response):
        if response.status_code == 200 and json.loads(response.content)["responseCode"] == 1:
            return True
        return False

    def does_handle_exist(self, response):
        if self.handle_success(response):
            return True
        return False

    def is_handle_empty(self, response):
        if response.status_code == 200 and json.loads(response.content)["responseCode"] == 200:
            return True
        return False

    def was_handle_created(self, response):
        if response.status_code == 201 and json.loads(response.content)["responseCode"] == 1:
            return True
        return False

    def handle_not_found(self, response):
        if response.status_code == 404 and json.loads(response.content)["responseCode"] == 100:
            return True
        return False

    def not_authenticated(self, response):
        if response.status_code == 401 or json.loads(response.content)["responseCode"] == 402:
            # need to put 'OR' because the HS responseCode is not always received!
            return True
        return False

    def values_not_found(self, response):
        if response.status_code == 400 and json.loads(response.content)["responseCode"] == 200:
            return True
        return False

    def handle_already_exists(self, response):
        if response.status_code == 409 & json.loads(response.content)["responseCode"] == 101:
            return True
        return False

    # Private methods:

    def __getHeaders(self, action):
        '''
        Create HTTP headers for different HTTP requests. Content-type and
            Accept are 'application/json', as the library is interacting with
            a REST API.

        :param action: Action for which to create the header ('GET', 'PUT',
            'DELETE', 'SEARCH').
        :return: dict containing key-value pairs, e.g. 'Accept',
            'Content-Type', etc. (depening on the action).
        '''
        head = None
        accept = 'application/json'
        content_type = 'application/json'

        if action is 'GET':
            head = {'Accept': accept}
        elif action is 'PUT':
            head = {'Content-Type': content_type,
                    'Authorization': 'Basic ' + self.__HS_auth_string}
        elif action is 'DELETE':
            head = {'Authorization': 'Basic ' + self.__HS_auth_string}
        elif action is 'SEARCH':
            head = {'Authorization': 'Basic ' + self.__revlookup_auth_string}
        else:
            LOGGER.debug('"_getHeader()": ACTION is unknown ('+action+')')

        return head

    def __send_handle_delete_request(self, handle, indices=None):
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

        url = self.make_handle_URL(handle, indices)
        if indices is not None and len(indices) > 0:
            LOGGER.info('DELETE Request for values '+str(indices))
        else:
            LOGGER.info('Deleting handle '+handle+'.')
        LOGGER.info('DELETE Request to '+url)
        LOGGER.debug('verify: '+str(self.__http_verify))
        resp = requests.delete(url, headers=self.__getHeaders('DELETE'),\
            verify=self.__http_verify)
        return resp

    def __send_handle_put_request(self, handle, list_of_entries, indices=None, overwrite=False):
        '''
        Send a HTTP PUT request to the handle server to write either an entire
            handle or to some specified values to an handle record, using the
            requests module.

        :param handle: The handle.
        :param list_of_entries: A list of handle record entries to be written,
         in the format [{"index":xyz, "type":"xyz", "data":"xyz"}] or similar.
        :param indices: Optional. A list of indices to delete. Defaults
         to None (i.e. the entire handle is deleted.). The list can
         contain integers or strings.
        :param overwrite: Optional. Whether the handle should be overwritten
         if it exists already.
        :return: The server's response.
        '''
        payload = json.dumps({'values':list_of_entries})

        if indices is not None:
            message = 'Writing handle values by index is not implemented'+\
                ' yet because the way the indices are interpreted by the'+\
                ' Handle Server may be modified soon. The entire handle'+\
                ' record has to be overwritten.'
            raise NotImplementedError(message)
            # TODO FIXME: As soon as the Handle System uses the correct indices
            # for overwriting, this may be implemented.
            # In HSv8 beta, the HS uses ?index=3 for overwriting index:4. If the
            # library used this and then the behaviour is changed, it would lead
            # to corrupt handle records, so we wait until the issue is fixed by
            # the Handle System.

        url = self.make_handle_URL(handle, overwrite=overwrite)
        LOGGER.info('PUT Request to '+url)
        LOGGER.debug('PUT Request payload: '+payload)
        LOGGER.debug('verify: '+str(self.__http_verify))
        resp = requests.put(url, data=payload, headers=self.__getHeaders('PUT'), verify=self.__http_verify)
        return resp

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

        url = self.make_handle_URL(handle, indices)
        LOGGER.info('GET Request to '+url)
        LOGGER.debug('verify: '+str(self.__http_verify))
        resp = requests.get(url, headers=self.__getHeaders('GET'), verify=self.__http_verify)
        return resp

    def __send_revlookup_get_request(self, query):

        solrurl = self.__solrbaseurl.rstrip('/')+'/'+self.__solrurlpath.strip('/')
        entirequery = solrurl+'?'+query.lstrip('?')

        hea = self.__getHeaders('SEARCH')
        resp = requests.get(entirequery, headers=hea, verify=self.__http_verify)
        return resp

    def __set_HS_auth_string(self, username, password):
        '''
        Creates and sets the authentication string for (write-)accessing the
            Handle Server. No return, the string is set as an attribute to
            the client instance.

        :param username: Username handle with index: index:prefix/suffix.
        :param password: The password contained in the index of the username
            handle.
        '''
        auth = self.create_authentication_string(username, password)
        self.__HS_auth_string = auth

    def __set_revlookup_auth_string(self, username, password):
        '''
        Creates and sets the authentication string for accessing the reverse
            lookup servlet. No return, the string is set as an attribute to
            the client instance.

        :param username: Username.
        :param password: Password.
        '''
        auth = self.create_authentication_string(username, password)
        self.__revlookup_auth_string = auth

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
            prohibited_indices = prohibited_indices-reserved_for_url
            start = 1
        elif hs_admin:
            prohibited_indices = prohibited_indices-reserved_for_admin
            start = 100

        # existing indices
        existing_indices = set()
        if list_of_entries is not None:
            for entry in list_of_entries:
                existing_indices.add(int(entry['index']))

        # find new index:
        all_prohibited_indices = existing_indices | prohibited_indices
        searchmax = max(start, max(all_prohibited_indices))+2
        for index in xrange(start, searchmax):
            if index not in all_prohibited_indices:
                return index

    def __create_entry(self, entrytype, data, index, ttl=None):
        '''
        Create an entry of any type except HS_ADMIN.

        :param entrytype: THe type of entry to create, e.g. 'URL' or
            'checksum' or ... Note: For entries of type 'HS_ADMIN', please
            use __create_admin_entry(). For type '10320/loc', please use
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
            raise b2handle.handleexceptions.IllegalOperationException(op, None, msg)

        entry = {'index':index, 'type':entrytype, 'data':data}

        if ttl is not None:
            entry['ttl'] = ttl

        return entry

    def __create_admin_entry(self, username, permissions, index, ttl=None):
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
        adminindex, adminhandle = self.remove_index(username)
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

    def __remove_URL_from_10320loc(self, url, list_of_entries, handle):
        '''
        Remove an URL from the handle record's "10320/loc" entry.
        If it exists several times in the entry, all occurences are removed.
        If the URL is not present, nothing happens.
        If after removing, there is no more URLs in the entry, the entry is
            removed.

        :param url: The URL to be removed.
        :param list_of_entries: A list of the existing entries (to find and
            remove the correct one).
        :param handle: Only for the exception message.
        :raise: GenericHandleError: If several 10320/loc exist (unlikely).
        '''

        # Find existing 10320/loc entries
        python_indices = self.__get_python_indices_for_key(
            '10320/loc',
            list_of_entries
        )

        num_removed = 0
        if len(python_indices) > 0:

            if len(python_indices) > 1:
                msg = str(len(python_indices))+' entries of type "10320/loc".'
                raise b2handle.handleexceptions.BrokenHandleRecordException(handle, msg)

            for index in python_indices:
                entry = list_of_entries.pop(index)
                xmlroot = ET.fromstring(entry['data']['value'])
                all_URL_elements = xmlroot.findall('location')
                for element in all_URL_elements:
                    if element.get('href') == url:
                        LOGGER.info('Removing URL '+url +' from 10320/loc.')
                        num_removed += 1
                        xmlroot.remove(element)
                remaining_URL_elements = xmlroot.findall('location')
                if len(remaining_URL_elements) == 0:
                    LOGGER.info("All URLs removed from 10320/loc.")
                    # TODO FIXME: If we start adapting the Handle Record by
                    # index (instead of overwriting the entire one), be careful
                    # to delete the ones that became empty!
                else:
                    entry['data']['value'] = ET.tostring(xmlroot)
                    LOGGER.debug(str(len(remaining_URL_elements))+' URLs'+\
                        ' left after removal operation.')
                    list_of_entries.append(entry)
        if num_removed == 0:
            LOGGER.info('No URLs removed from 10320/loc.')
        else:
            message = 'The URL "'+url+'" was removed '+str(num_removed)+\
            ' times from 10320/loc.'
            message = message.replace('1 times', 'once')

    def __add_URL_to_10320loc(self, url, list_of_entries, handle=None, weight=None, http_role=None, **kvpairs):
        '''
        Add a url to the handle record's "10320/loc" entry.
            If no 10320/loc entry exists, a new one is created (using the
            default "chooseby" attribute, if configured).
            If the URL is already present, it is not added again, but
            the attributes (e.g. weight) are updated/added.
            If the existing 10320/loc entry is mal-formed, an exception will be
            thrown (xml.etree.ElementTree.ParseError)
            Note: In the unlikely case that several "10320/loc" entries exist,
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
        :raise: GenericHandleError: If several 10320/loc exist (unlikely).

        '''

        # Find existing 10320/loc entry or create new
        indices = self.__get_python_indices_for_key('10320/loc', list_of_entries)
        makenew = False
        entry = None
        if len(indices) == 0:
            index = self.__make_another_index(list_of_entries)
            entry = self.__create_entry('10320/loc', 'add_later', index)
            makenew = True
        else:
            if len(indices) > 1:
                msg = 'There is '+str(len(indices))+' 10320/loc entries.'
                raise b2handle.handleexceptions.BrokenHandleRecordException(handle, msg)
            ind = indices[0]
            entry = list_of_entries.pop(ind)

        # Get xml data or make new:
        xmlroot = None
        if makenew:
            xmlroot = ET.Element('locations')
            if self.__10320loc_chooseby is not None:
                xmlroot.set('chooseby', self.__10320loc_chooseby)
        else:
            try:
                xmlroot = ET.fromstring(entry['data']['value'])
            except TypeError:
                xmlroot = ET.fromstring(entry['data'])
        LOGGER.debug("xmlroot is (1) "+ET.tostring(xmlroot))

        # Check if URL already there, if not, add it!
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
        if location_element is None:
            location_id = 0
            for existing_id in existing_location_ids:
                if location_id == existing_id:
                    location_id += 1
            location_element = ET.SubElement(xmlroot, 'location')
            LOGGER.debug("location_element is (1) "+ET.tostring(location_element))
            location_element.set('id', str(location_id))
            LOGGER.debug("location_element is (2) "+ET.tostring(location_element))
            location_element.set('href', url)
            LOGGER.debug("location_element is (3) "+ET.tostring(location_element))
        self.__set_or_adapt_10320loc_attributes(location_element, weight, http_role, **kvpairs)
        # FIXME: If we start adapting the Handle Record by index (instead of
        # overwriting the entire one), be careful to add and/or overwrite!

        # (Re-)Add entire 10320 to entry, add entry to list of entries:
        LOGGER.debug("xmlroot is (2) "+ET.tostring(xmlroot))
        entry['data'] = ET.tostring(xmlroot)
        list_of_entries.append(entry)

    def __set_or_adapt_10320loc_attributes(self, locelement, weight=None, http_role=None, **kvpairs):
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
            LOGGER.debug('weight ('+str(type(weight))+'): '+str(weight))
            weight = float(weight)
            if weight < 0  or weight > 1:
                default = 1
                LOGGER.info('Invalid weight ('+str(weight)+\
                    '), using default value ('+str(default)+') instead.')
                weight = default
            weight = str(weight)
            locelement.set('weight', weight)

        if http_role is not None:
            locelement.set('http_role', http_role)

        for key, value in kvpairs.iteritems():
            locelement.set(key, str(value))

    def string_to_bool(self, string):
        dic = {'false':False, 'true':True}
        if string is True or string is False:
            return string
        else:
            return dic[string.lower()]