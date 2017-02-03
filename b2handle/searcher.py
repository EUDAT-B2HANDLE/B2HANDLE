'''
This module provides the class Searcher
which interacts with a Handle Search
Servlet.

Author: Merret Buurman (DKRZ), 2015-2016

'''

import logging
import re
import requests
import json
import b2handle
from past.builtins import xrange
from b2handle.handleexceptions import ReverseLookupException

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(b2handle.util.NullHandler())
REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.propagate = False
REQUESTLOGGER.addHandler(b2handle.util.NullHandler())

class Searcher(object):
    '''
    This class interacts with a Handle Search
        Servlet.

    As such a Search Servlet is not provided by
    the Handle System, this class caters to a
    custom Search Servlet.

    '''

    def __init__(self, **args):

        b2handle.util.log_instantiation(LOGGER, 'Searcher', args, ['password','reverselookup_password'])

        optional_args = [
            'reverselookup_baseuri',
            'reverselookup_url_extension',
            'handle_server_url',
            'reverselookup_username',
            'username',
            'reverselookup_password',
            'password',
            'allowed_search_keys',
            'HTTPS_verify'
        ]
        b2handle.util.add_missing_optional_args_with_value_none(args, optional_args)

        # Args that the constructor understands:
        self.__reverselookup_baseuri = None
        self.__reverselookup_url_extension = None
        self.__allowed_search_keys = None
        self.__HTTPS_verify = None
        self.__user = None
        self.__password = None

        # Other attributes:
        self.__has_search_access = False
        self.__handle_system_username_used = False
        self.__handle_system_password_used = False
        self.__revlookup_auth_string = None
        self.__header = None
        self.__session = None
        self.__search_url = None

        # Defaults:
        defaults = {
            'allowed_search_keys': ['URL', 'CHECKSUM'],
            'HTTPS_verify': True,
            'reverselookup_url_extension': '/hrls/handles/',
        }

        # Set them:
        self.__store_args_or_set_to_defaults(args, defaults)
        self.__setup_search_access()

        LOGGER.debug('End of instantiation of the search module.')

    def __setup_search_access(self):
        self.__check_and_set_search_access()
        self.__session = requests.Session()
        if self.__session is None:
            LOGGER.info('Session could not be created.')
        else:
            LOGGER.debug('Session was created.')

    def __check_and_set_search_access(self):
        user_and_pw_exist = self.__check_and_set_search_authentication()
        url_exists = self.__check_and_set_search_url()

        if user_and_pw_exist and url_exists:
            self.__has_search_access = True

    def __check_and_set_search_authentication(self):
        user_and_pw_exst = False

        if self.__user is not None and self.__password is not None:
            self.__set_revlookup_auth_string(self.__user, self.__password)
            self.__header = {'Authorization': 'Basic ' + self.__revlookup_auth_string}
            LOGGER.info('Reverse lookup authentication is set.')
            return True

        else:
            msg = 'Reverse lookup not possible.'
            if self.__user is None and self.__password is None:
                LOGGER.info(msg+' Neither username nor password were provided.')
            elif self.__user is None:
                LOGGER.info(msg+' Username not provided. Password is '+str(self.__password))
            else:
                LOGGER.info(msg+' Password not provided. Username is '+str(self.__user))
            return False

    def __check_and_set_search_url(self):
        if (self.__reverselookup_baseuri is not None and
            self.__reverselookup_url_extension is not None):
            
            self.__search_url = (
                self.__reverselookup_baseuri.rstrip('/')+'/'+
                self.__reverselookup_url_extension.strip('/')
            )
            return True
            LOGGER.info('Reverse lookup endpoint set to '+str(self.__search_url))
        else:
            msg = 'Reverse lookup not possible.'
            if (self.__reverselookup_baseuri is None and
                self.__reverselookup_url_extension is None):
                LOGGER.info(msg+' No URL for reverse lookup provided.')
            elif self.__reverselookup_baseuri is None:
                LOGGER.info(msg+' No URL for reverse lookup provided.')
            else:
                LOGGER.info(msg+' No URL path for reverse lookup provided.')
            return False

    def get_search_endpoint(self):
        if self.__has_search_access:
            return self.__search_url
        else:
            LOGGER.error(
                'Searching not possible. Reason: No access '+
                'to search system (endpoint: '+
                str(self.__search_url)+').'
            )
            return None

    def __store_args_or_set_to_defaults(self, args, defaults):

        LOGGER.debug('Setting the attributes:')

        if args['HTTPS_verify'] is not None: # Without this check, a passed "False" is not found!
            self.__HTTPS_verify = b2handle.util.get_valid_https_verify(
                args['HTTPS_verify']
            )
            LOGGER.info(' - https_verify set to: '+str(self.__HTTPS_verify))
        else:
            self.__HTTPS_verify = defaults['HTTPS_verify']
            LOGGER.info(' - https_verify set to default: '+str(self.__HTTPS_verify))

        if args['allowed_search_keys'] is not None: # Without this check, empty lists are not found!
            self.__allowed_search_keys = args['allowed_search_keys']
            LOGGER.info(' - allowed_search_keys set to: '+str(self.__allowed_search_keys))
        else:
            self.__allowed_search_keys = defaults['allowed_search_keys']
            LOGGER.info(' - allowed_search_keys set to default: '+str(self.__allowed_search_keys))

        if args['reverselookup_baseuri']:
            self.__reverselookup_baseuri = args['reverselookup_baseuri']
            LOGGER.info(' - solrbaseurl set to: '+self.__reverselookup_baseuri)
        elif 'handle_server_url' in args.keys() and args['handle_server_url'] is not None:
            self.__reverselookup_baseuri = args['handle_server_url']
            LOGGER.info(' - solrbaseurl set to same as handle server: '+str(self.__reverselookup_baseuri))
        else:
            LOGGER.info(' - solrbaseurl: No default.')

        if args['reverselookup_url_extension']:
            self.__reverselookup_url_extension = args['reverselookup_url_extension']
            LOGGER.info(' - reverselookup_url_extension set to: '+self.__reverselookup_url_extension)
        else:
            self.__reverselookup_url_extension = defaults['reverselookup_url_extension']
            LOGGER.info(' - reverselookup_url_extension set to default: '+self.__reverselookup_url_extension)

        # Authentication reverse lookup:
        #   If specified, use it.
        #   Else: Try using handle system authentication
        #   Else: search_handle does not work and will raise an exception.

        if args['reverselookup_username']:
            self.__user = args['reverselookup_username']
            LOGGER.info(' - reverselookup_username set to: '+self.__user)
        elif args['username']:
            self.__user = args['username']
            self.__handle_system_username_used = True
            LOGGER.info(' - reverselookup_username set to handle server username: '+self.__user)
        else:
            LOGGER.info(' - reverselookup_username: Not specified. No default.')

        if args['reverselookup_password']:
            self.__password = args['reverselookup_password']
            LOGGER.info(' - reverselookup_password set.')
        elif args['password']:
            self.__password = args['password']
            self.__handle_system_password_used = True
            LOGGER.info(' - reverselookup_password set to handle server password.')
        else:
            LOGGER.info(' - reverselookup_password: Not specified. No default.')


    def search_handle(self, **args):
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
          * list_of_handles = search_handle('http://www.foo.com')
          * list_of_handles = search_handle('http://www.foo.com', CHECKSUM=99999)
          * list_of_handles = search_handle(URL='http://www.foo.com', CHECKSUM=99999)

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
        if self.__has_search_access:
            return self.__search_handle(**args)
        else:
            LOGGER.error(
                'Searching not possible. Reason: No access '+
                'to search system (endpoint: '+
                str(self.__search_url)+').'
            )
            return None

    def __search_handle(self, **args):

        # Prefix specified? Remove them from the key value pairs to be searched.
        prefix = None
        if 'prefix' in args.keys():
            prefix = args.pop('prefix')

        # Any fulltext search terms specified? Remove them from the key value pairs to be searched.
        fulltext_searchterms = []
        if 'searchterms' in args.keys():
            fulltext_searchterms = args.pop('searchterms')

        # Check if there is any key-value pairs to be searched.
        if len(args) == 0:
            LOGGER.debug('search_handle: No key value pair was specified.')
            msg = 'No search terms have been specified. Please specify'+\
                ' at least one key-value-pair.'
            raise ReverseLookupException(msg=msg)
        else:
            isnone = b2handle.util.return_keys_of_value_none(args)
            if len(isnone) > 0:
                LOGGER.debug('search_handle: These keys had value None: '+str(isnone))
                args = b2handle.util.remove_value_none_from_dict(args)
                if len(args) == 0:
                    LOGGER.debug('search_handle: No key value pair with valid value was specified.')
                    msg = ('No search terms have been specified. Please specify'
                           ' at least one key-value-pair.')
                    raise ReverseLookupException(msg=msg)

        # Perform the search:
        list_of_handles = []
        LOGGER.debug('search_handle: key-value-pairs: '+str(args))
        query = self.create_revlookup_query(*fulltext_searchterms, **args)

        if query is None:
            msg = 'No search query was specified'
            raise ReverseLookupException(msg=msg)

        resp = self.__send_revlookup_get_request(query)

        # Check for undefined fields
        regex = 'RemoteSolrException: Error from server at .+: undefined field .+'
        match = re.compile(regex).search(str(resp.content))
        if match is not None:
            undefined_field = resp.content.split('undefined field ')[1]
            msg = 'Tried to search in undefined field "'+undefined_field+'"..'
            raise ReverseLookupException(msg=msg, query=query, response=resp)

        if resp.status_code == 200:
            try:
                list_of_handles = json.loads(resp.content)
            except ValueError:
                msg = 'The response is not JSON.'
                raise ReverseLookupException(msg=msg, query=query, response=resp)

        elif resp.status_code == 401:
            msg = 'Authentication failed.'
            if self.__handle_system_username_used or self.__handle_system_password_used:
                msg += (' If the Reverse Lookup Servlet you are'
                        ' using does not accept the same username and/or password'
                        ' as the Handle Server, please provide its username and/or'
                        ' password separately when instantiating the client')
            else:
                msg += ' You need to specify a username and password to search'
            raise ReverseLookupException(msg=msg, query=query, response=resp)

        elif resp.status_code == 404:
            msg = 'Wrong search servlet URL ('+resp.request.url+')'
            regex = 'The handle you requested.+cannot be found'
            match = re.compile(regex, re.DOTALL).search(str(resp.content))
            if match is not None:
                msg += '. It seems you reached a Handle Server'
            raise ReverseLookupException(msg=msg, query=query, response=resp)

        else:
            raise ReverseLookupException(query=query, response=resp)

        # Filter prefixes:
        if prefix is not None:
            LOGGER.debug('search_handle: Restricting search to prefix '+prefix)
            filteredlist_of_handles = []
            for i in xrange(len(list_of_handles)):
                if list_of_handles[i].split('/')[0] == prefix:
                    filteredlist_of_handles.append(list_of_handles[i])
            list_of_handles = filteredlist_of_handles

        return list_of_handles

    def create_revlookup_query(self, *fulltext_searchterms, **keyvalue_searchterms):
        '''
        Create the part of the solr request that comes after the question mark,
        e.g. ?URL=*dkrz*&CHECKSUM=*abc*. If allowed search keys are
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
        LOGGER.debug('create_revlookup_query...')

        allowed_search_keys = self.__allowed_search_keys
        only_search_for_allowed_keys = False
        if len(allowed_search_keys) > 0:
            only_search_for_allowed_keys = True

        fulltext_searchterms_given = True
        fulltext_searchterms = b2handle.util.remove_value_none_from_list(fulltext_searchterms)
        if len(fulltext_searchterms) == 0:
            fulltext_searchterms_given = False
        
        if fulltext_searchterms_given:
            msg = 'Full-text search is not implemented yet.'+\
                ' The provided searchterms '+str(fulltext_searchterms)+\
                ' can not be used.'
            raise ReverseLookupException(msg=msg)

        keyvalue_searchterms_given = True
        keyvalue_searchterms = b2handle.util.remove_value_none_from_dict(keyvalue_searchterms)
        if len(keyvalue_searchterms) == 0:
            keyvalue_searchterms_given = False

        if not keyvalue_searchterms_given and not fulltext_searchterms_given:
            msg = 'No search terms have been specified. Please specify'+\
                ' at least one key-value-pair.'
            raise ReverseLookupException(msg=msg)

        counter = 0
        query = '?'
        for key, value in keyvalue_searchterms.items():

            if only_search_for_allowed_keys and key not in allowed_search_keys:
                msg = 'Cannot search for key "'+key+'". Only searches '+\
                    'for keys '+str(allowed_search_keys)+' are implemented.'
                raise ReverseLookupException(msg=msg)
            else:
                query = query+'&'+key+'='+value
                counter += 1

        query = query.replace('?&', '?')
        LOGGER.debug('create_revlookup_query: query: '+query)
        if counter == 0: # unreachable?
            msg = 'No valid search terms have been specified.'
            raise ReverseLookupException(msg=msg)
        return query

    def __set_revlookup_auth_string(self, username, password):
        '''
        Creates and sets the authentication string for accessing the reverse
            lookup servlet. No return, the string is set as an attribute to
            the client instance.

        :param username: Username.
        :param password: Password.
        '''
        auth = b2handle.utilhandle.create_authentication_string(username, password)
        self.__revlookup_auth_string = auth

    def __send_revlookup_get_request(self, query):

        solrurl = self.__search_url
        entirequery = solrurl+'?'+query.lstrip('?')

        head = self.__header
        veri = self.__HTTPS_verify
        resp = self.__session.get(entirequery, headers=head, verify=veri)
        self.__log_request_response_to_file(
            logger=REQUESTLOGGER,
            op='SEARCH',
            handle='',
            url=entirequery,
            headers=head,
            verify=veri,
            resp=resp
        )
        return resp

    def __log_request_response_to_file(self, **args):
        message = b2handle.utilhandle.make_request_log_message(**args)
        args['logger'].info(message)

