'''
This moodule contains the class HandleSystemConnector which is
    responsible for the library's interaction with the Handle
    Server.

Author: Merret Buurman (DKRZ), 2015-2016

'''

import json
import logging
import requests
import os
import b2handle
from b2handle.handleexceptions import HandleNotFoundException, GenericHandleError, HandleAuthenticationError, CredentialsFormatError
from b2handle.compatibility_helper import decoded_response
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(b2handle.util.NullHandler())
REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.propagate = False
REQUESTLOGGER.addHandler(b2handle.util.NullHandler())


class HandleSystemConnector(object):
    '''
    HandleSystemConnector handles the interaction of the b2handle
    library with the handle server. It holds the necessary
    information (URL, credentials, defaults) and handles
    some exceptions.

    '''

    def __init__(self, **args):

        b2handle.util.log_instantiation(LOGGER, 'HandleSystemConnector', args, ['password','reverselookup_password'])

        # Possible arguments:
        optional_args = [
            'handle_server_url',
            'REST_API_url_extension',
            'HTTPS_verify',
            'username',
            'password',
            'private_key',
            'certificate_only',
            'certificate_and_key'
        ]
        b2handle.util.add_missing_optional_args_with_value_none(args, optional_args)

        # Defaults for args:
        defaults = {
            'handle_server_url': 'https://hdl.handle.net',
            'REST_API_url_extension': '/api/handles/',
            'HTTPS_verify': True,
        }

        # Args that the constructor understands:
        self.__handle_server_url = None
        self.__REST_API_url_extension = None
        self.__HTTPS_verify = None
        self.__username = None
        self.__password = None
        self.__private_key = None
        self.__certificate_only = None
        self.__certificate_and_key = None
        self.__handle_connector = None

        # Other attributes:
        self.__basic_authentication_string = None
        self.__cert_object = None
        self.__has_write_access = False
        self.__auth_methods = dict(user_pw='user_pw', cert='client_cert')
        self.__authentication_method = None
        self.__session = requests.Session()
        self.__no_auth_message = 'No credentials passed. Read access only.'
        self.__first_request = True

        # Needed for read and write access:
        self.__store_args_or_set_to_defaults(args, defaults)

        # If write access, do some additional setup:
        if self.__check_if_write_access(args):
            self.__setup_for_writeaccess(args)

        LOGGER.debug('End of instantiation of the handle system connector.')


    # Helpers for init method:

    def __store_args_or_set_to_defaults(self, args, defaults):

        LOGGER.debug('Setting the attributes:')

        # Useful for read and write:

        if args['handle_server_url']:
            self.__handle_server_url = args['handle_server_url']
            LOGGER.info(' - handle_server_url set to '+self.__handle_server_url)
        else:
            self.__handle_server_url = defaults['handle_server_url']
            LOGGER.info(' - handle_server_url set to default: '+self.__handle_server_url)


        if args['REST_API_url_extension']:
            self.__REST_API_url_extension = args['REST_API_url_extension']
            LOGGER.info(' - url_extension_REST_API set to: '+self.__REST_API_url_extension)
        else:
            self.__REST_API_url_extension = defaults['REST_API_url_extension']
            LOGGER.info(' - url_extension_REST_API set to default: '+self.__REST_API_url_extension)


        if args['HTTPS_verify'] is not None:
            self.__HTTPS_verify = b2handle.util.get_valid_https_verify(
                args['HTTPS_verify']
            )
            LOGGER.info(' - https_verify set to: '+str(self.__HTTPS_verify))
        else:
            self.__HTTPS_verify = defaults['HTTPS_verify']
            LOGGER.info(' - https_verify set to default: '+str(self.__HTTPS_verify))


        # Useful for write:

        if args['password']:
            self.__password = args['password']
            LOGGER.info(' - password set.')

        if args['username']:
            self.__username = args['username']
            LOGGER.info(' - username set to: '+self.__username)

        if args['certificate_only']:
            self.__certificate_only = args['certificate_only']
            LOGGER.info(' - certificate_only set to: '+str(self.__certificate_only))

        if args['private_key']:
            self.__private_key = args['private_key']
            LOGGER.info(' - private_key set to: '+str(self.__private_key))

        if args['certificate_and_key']:
            self.__certificate_and_key = args['certificate_and_key']
            LOGGER.info(' - certificate_and_key set to: '+str(self.__certificate_and_key))

    def __check_if_write_access(self, args):
        write_access_argnames = ['username', 'password', 'certificate_only', 'private_key', 'certificate_and_key']
        for argname in write_access_argnames:
            if argname in args.keys() and args[argname] is not None:
                LOGGER.debug('Connector got argument "'+argname+'", so write access is desired.')
                return True
        return False

    def __setup_for_writeaccess(self, args):

        self.__has_write_access = True

        # Handle server URL:
        if args['handle_server_url'] is None:
            raise TypeError('No handle_server_url given. Default URL not ok for write access.')

        # Find out authentication method:
        self.__authentication_method = self.__which_authentication_method()

        # Authentication method dependent settings:
        if self.__authentication_method == self.__auth_methods['user_pw']:
            self.__setup_for_auth_by_user_and_pw()
        elif self.__authentication_method == self.__auth_methods['cert']:
            self.__setup_for_auth_by_clientcertificate()
        elif self.__authentication_method is None:
            self.__has_write_access = False
        else:
            msg = 'Unknown authentication method: "'+self.__authentication_method+'".'
            self.__has_write_access = False

    def __setup_for_auth_by_user_and_pw(self):

        # Check username:
        b2handle.utilhandle.check_handle_syntax_with_index(self.__username)
        self.check_if_username_exists(self.__username)

        # Make Basic Auth String:
        self.__set_basic_auth_string(self.__username, self.__password)

    def __setup_for_auth_by_clientcertificate(self):

        if self.__certificate_and_key:
            self.__cert_object = self.__certificate_and_key
            if not os.path.isfile(self.__certificate_and_key):
                msg = 'The certificate file was not found at the specified path: '+self.__certificate_and_key
                raise CredentialsFormatError(msg=msg)

        else:
            self.__cert_object = (self.__certificate_only, self.__private_key)
            msg = ''
            if not os.path.isfile(self.__certificate_only):
                msg += 'The certificate file was not found at the specified path: '+self.__certificate_only
            if not os.path.isfile(self.__private_key):
                msg += 'The private key file was not found at the specified path: '+self.__private_key
            if msg is not '':
                raise CredentialsFormatError(msg=msg)

    def __which_authentication_method(self):

        authentication_method = None

        # Username and Password
        if self.__username and self.__password:
            authentication_method = self.__auth_methods['user_pw']

        # Certificate file and Key file
        if self.__certificate_only and self.__private_key:
            authentication_method = self.__auth_methods['cert']

        # Certificate and Key in one file
        if self.__certificate_and_key:
            authentication_method = self.__auth_methods['cert']

        # None was provided:
        if authentication_method is None:
            msg = 'We could not identify which authentication method you would like to use'
            if self.__username is None and self.__password:
                msg += '.\nUsername was provided, but no password'
            elif self.__password is None and self.__username:
                msg += '.\nPassword was provided, but no username'
            if self.__certificate_only is None and self.__private_key:
                msg += '.\nA client certificate was provided, but no private key'
            elif self.__private_key is None and not self.__certificate_only is None:
                msg += '.\nA private key was provided, but no client certificate'
            self.__no_auth_message = msg
            LOGGER.debug(msg)
            self.__has_write_access = False
        else:
            LOGGER.debug('Authentication method: '+authentication_method)

        return authentication_method

    def __set_basic_auth_string(self, username, password):
        '''
        Creates and sets the authentication string for (write-)accessing the
            Handle Server. No return, the string is set as an attribute to
            the client instance.

        :param username: Username handle with index: index:prefix/suffix.
        :param password: The password contained in the index of the username
            handle.
        '''
        auth = b2handle.utilhandle.create_authentication_string(username, password)
        self.__basic_authentication_string = auth


    # API methods:

    def send_handle_get_request(self, handle, indices=None):
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


        # Assemble required info:
        url = self.make_handle_URL(handle, indices)
        LOGGER.debug('GET Request to '+url)
        head = self.__get_headers('GET')
        veri = self.__HTTPS_verify

        # Send the request
        if self.__cert_needed_for_get_request():
            # If this is the first request and the connector uses client cert authentication, we need to send the cert along
            # in the first request that builds the session.
            resp = self.__session.get(url, headers=head, verify=veri, cert=self.__cert_object)
        else:
            # Normal case:
            resp = self.__session.get(url, headers=head, verify=veri)
    
        # Log and return
        self.__log_request_response_to_file(
            logger=REQUESTLOGGER,
            op='GET',
            handle=handle,
            url=url,
            headers=head,
            verify=veri,
            resp=resp
            )
        self.__first_request = False
        return resp

    def __cert_needed_for_get_request(self):
        if (self.__first_request) and (self.__has_write_access) and (self.__authentication_method == self.__auth_methods['cert']):
            return True
        else:
            return False


    def send_handle_put_request(self, **args):
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

        # Check if we have write access at all:
        if not self.__has_write_access:
            raise HandleAuthenticationError(msg=self.__no_auth_message)

        # Check args:
        mandatory_args = ['handle', 'list_of_entries']
        optional_args = ['indices', 'op', 'overwrite']
        b2handle.util.add_missing_optional_args_with_value_none(args, optional_args)
        b2handle.util.check_presence_of_mandatory_args(args, mandatory_args)
        handle = args['handle']
        list_of_entries = args['list_of_entries']
        indices = args['indices']
        op = args['op']
        overwrite = args['overwrite'] or False

        # Make necessary values:
        url = self.make_handle_URL(handle, indices, overwrite=overwrite)
        LOGGER.debug('PUT Request to '+url)
        payload = json.dumps({'values':list_of_entries})
        LOGGER.debug('PUT Request payload: '+payload)
        head = self.__get_headers('PUT')
        LOGGER.debug('PUT Request headers: '+str(head))
        veri = self.__HTTPS_verify

        # Send request to server:
        resp = self.__send_put_request_to_server(url, payload, head, veri, handle)
        if b2handle.hsresponses.is_redirect_from_http_to_https(resp):
            resp = self.__resend_put_request_on_302(payload, head, veri, handle, resp)

        # Check response for authentication issues:
        if b2handle.hsresponses.not_authenticated(resp):
            raise HandleAuthenticationError(
                operation=op,
                handle=handle,
                response=resp,
                username=self.__username
            )
        self.__first_request = False
        return resp, payload

    def __send_put_request_to_server(self, url, payload, head, veri, handle):
        resp = None
        allow_redirects = False
        if self.__authentication_method == self.__auth_methods['user_pw']:
            resp = self.__session.put(url, data=payload, headers=head, verify=veri, allow_redirects=allow_redirects)
        elif self.__authentication_method == self.__auth_methods['cert']:
            resp = self.__session.put(url, data=payload, headers=head, verify=veri, cert=self.__cert_object, allow_redirects=allow_redirects)
        self.__log_request_response_to_file(
            logger=REQUESTLOGGER,
            op='PUT',
            handle=handle,
            url=url,
            headers=head,
            verify=veri,
            resp=resp,
            payload=payload)
        return resp

    def __resend_put_request_on_302(self, payload, head, veri, handle, resp):
        # Check response for 302 redirect.
        # In that case we have to manually reissue the request to make
        # sure it is done via PUT and not GET
        # as the requests library makes all 302 redirects to GET and then we get a wrong 200-OK!
        newurl = resp.headers['location']
        resp = self.__send_put_request_to_server(newurl, payload, head, veri, handle)

    def send_handle_delete_request(self, **args):
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

        # Check if we have write access at all:
        if not self.__has_write_access:
            raise HandleAuthenticationError(msg=self.__no_auth_message)

        # Check args:
        mandatory_args = ['handle']
        optional_args = ['indices', 'op']
        b2handle.util.add_missing_optional_args_with_value_none(args, optional_args)
        b2handle.util.check_presence_of_mandatory_args(args, mandatory_args)
        handle = args['handle']
        indices = args['indices']
        op = args['op']

        # Make necessary values:
        url = self.make_handle_URL(handle, indices)
        if indices is not None and len(indices) > 0:
            LOGGER.debug('__send_handle_delete_request: Deleting values '+str(indices)+' from handle '+handle+'.')
        else:
            LOGGER.debug('__send_handle_delete_request: Deleting handle '+handle+'.')
        LOGGER.debug('DELETE Request to '+url)
        head = self.__get_headers('DELETE')
        veri = self.__HTTPS_verify

        # Make request:
        resp = None
        if self.__authentication_method == self.__auth_methods['user_pw']:
            resp = self.__session.delete(url, headers=head, verify=veri)
        elif self.__authentication_method == self.__auth_methods['cert']:
            resp = self.__session.delete(url, headers=head, verify=veri, cert=self.__cert_object)
        self.__log_request_response_to_file(
            logger=REQUESTLOGGER,
            op='DELETE',
            handle=handle,
            url=url,
            headers=head,
            verify=veri,
            resp=resp
        )

        # Check response for authentication issues:
        if b2handle.hsresponses.not_authenticated(resp):
            raise HandleAuthenticationError(
                operation=op,
                handle=handle,
                response=resp,
                username=self.__username
            )
        self.__first_request = False
        return resp

    def check_if_username_exists(self, username):
        '''
        Check if the username handles exists.

        :param username: The username, in the form index:prefix/suffix
        :raises: :exc:`~b2handle.handleexceptions.HandleNotFoundException`
        :raises: :exc:`~b2handle.handleexceptions.GenericHandleError`
        :return: True. If it does not exist, an exception is raised.

        *Note:* Only the existence of the handle is verified. The existence or
        validity of the index is not checked, because entries containing
        a key are hidden anyway.
        '''
        LOGGER.debug('check_if_username_exists...')

        _, handle = b2handle.utilhandle.remove_index_from_handle(username)

        resp = self.send_handle_get_request(handle)
        resp_content = decoded_response(resp)
        if b2handle.hsresponses.does_handle_exist(resp):
            handlerecord_json = json.loads(resp_content)
            if not handlerecord_json['handle'] == handle:
                raise GenericHandleError(
                    operation='Checking if username exists',
                    handle=handle,
                    reponse=resp,
                    msg='The check returned a different handle than was asked for.'
                )
            return True
        elif b2handle.hsresponses.handle_not_found(resp):
            msg = 'The username handle does not exist'
            raise HandleNotFoundException(handle=handle, msg=msg, response=resp)
        else:
            op = 'checking if handle exists'
            msg = 'Checking if username exists went wrong'
            raise GenericHandleError(operation=op, handle=handle, response=resp, msg=msg)

    def __get_headers(self, action):
        '''
        Create HTTP headers for different HTTP requests. Content-type and
            Accept are 'application/json', as the library is interacting with
            a REST API.

        :param action: Action for which to create the header ('GET', 'PUT',
            'DELETE', 'SEARCH').
        :return: dict containing key-value pairs, e.g. 'Accept',
            'Content-Type', etc. (depening on the action).
        '''
        header = {}
        accept = 'application/json'
        content_type = 'application/json'

        if action is 'GET':
            header['Accept'] = accept


        elif action is 'PUT' or action is 'DELETE':

            if self.__authentication_method == self.__auth_methods['cert']:
                header['Authorization'] = 'Handle clientCert="true"'

            elif self.__authentication_method == self.__auth_methods['user_pw']:
                header['Authorization'] = 'Basic ' + self.__basic_authentication_string

            if action is 'PUT':
                header['Content-Type'] = content_type


        else:
            LOGGER.debug('__getHeader: ACTION is unknown ('+action+')')
        return header

    def make_handle_URL(self, handle, indices=None, overwrite=None, other_url=None):
        '''
        Create the URL for a HTTP request (URL + query string) to request
        a specific handle from the Handle Server.

        :param handle: The handle to access.
        :param indices: Optional. A list of integers or strings. Indices of
            the handle record entries to read or write. Defaults to None.
        :param overwrite: Optional. If set, an overwrite flag will be appended
            to the URL ({?,&}overwrite=true or {?,&}overwrite=false). If not set, no
            flag is set, thus the Handle Server's default behaviour will be
            used. Defaults to None.
        :param other_url: Optional. If a different Handle Server URL than the
            one specified in the constructor should be used. Defaults to None.
            If set, it should be set including the URL extension,
            e.g. '/api/handles/'.
        :return: The complete URL, e.g.
         'http://some.handle.server/api/handles/prefix/suffix?index=2&index=6&overwrite=false
        '''
        LOGGER.debug('make_handle_URL...')
        separator = '?'

        if other_url is not None:
            url = other_url
        else:
            url = self.__handle_server_url.strip('/') +'/'+\
                self.__REST_API_url_extension.strip('/')
        url = url.strip('/')+'/'+ handle

        if indices is None:
            indices = []
        if len(indices) > 0:
            for index in indices:
                url = url+separator+'index='+str(index)
                separator = '&'

        if overwrite is not None:
            if overwrite:
                url = url+separator+'overwrite=true'
            else:
                url = url+separator+'overwrite=false'

        return url

    def __log_request_response_to_file(self, **args):
        message = b2handle.utilhandle.make_request_log_message(**args)
        args['logger'].info(message)
