'''
Created on 2015-07-02
Started implementing 2015-07-15
Last updated: 2015-08-26
'''

from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import CredentialsFormatError
import util
import json

class PIDClientCredentials(object):
    '''
    Provides authentication information to access a Handle server, either by
        specifying username and password or by providing a json file containing
        the relevant information.

    '''
    # QUESTION: Old epic client had an (unimplemented) option to "...getting
    #   credential store in iRODS". Needed?
    # QUESTION: Specify accept_format? Catch IO Exception?

    @staticmethod
    def load_from_JSON(json_filename):
        '''
        Create a new instance of a PIDClientCredentials with information read
            from a local JSON file.

        :param json_filename: The path to the json credentials file. The json
            file should have the following format:
            {
                "baseuri": "https://url.to.your.handle.server",
                "username": "index:prefix/suffix",
                "password": "ZZZZZZZ",
                "prefix": "prefix_to_use_for_writing_handles",
                "handleowner": "username_to_own_handles"
            }
            The parameters 'prefix' and 'handleowner' are optional and default to None.
            If 'prefix' is not given, the prefix has to be specified each time a handle is
            created or modified.
            If 'handleowner' is given, it is written into the created handles' HS_ADMIN.
            If it is not given, the username is given. This parameter allows a user to create 
            handles that are then modifiable by a larger user group than just himself, e.g.
            user John Doe creates the handle, but wants all his colleagues to be able to
            modify it.
            Any additional key-value-pairs are stored in the instance as
            config.
        :raises: CredentialsFormatError
        :raises: HandleSyntaxError
        :return: An instance.
        '''

        jsonfilecontent = json.loads(open(json_filename, 'r').read())
        PIDClientCredentials.check_credentials_format(jsonfilecontent)

        baseuri = jsonfilecontent.pop('baseuri')
        username = jsonfilecontent.pop('username')
        password = jsonfilecontent.pop('password')
        prefix = None
        handleowner = None
        if 'prefix' in jsonfilecontent:
            prefix = jsonfilecontent.pop('prefix')
        if 'handleowner' in jsonfilecontent:
            handleowner = jsonfilecontent.pop('handleowner')
        instance = PIDClientCredentials(
            baseuri,
            username,
            password,
            prefix,
            handleowner,
            **jsonfilecontent
        )
        return instance


    @staticmethod
    def check_credentials_format(credentials_dict):
        '''
        Check whether the credentials contain all necessary items.

        :param credentials_dict: A dictionary of the credentials.
        :raise: CredentialsFormatError, if the credentials lack information.
        '''
        missing = []
        mandatoryitems = ['baseuri', 'username', 'password']
        for item in mandatoryitems:
            if not item in credentials_dict:
                missing.append(item)
            elif credentials_dict[item] == '':
                missing.append(item)
        if len(missing) > 0:
            msg = 'The following item(s) were empty or missing in the'+\
                ' provided credentials file: '+str(missing)
            raise CredentialsFormatError(msg=msg)

    def __init__(self, handle_server_url, username, password, prefix=None, handleowner=None, **config):
        '''
        Initialize client credentials instance with Handle server url,
            username and password.

        :param handle_server_url: URL to your handle server
        :param username: User information in the format "index:prefix/suffix"
        :param password: Password.
        :param prefix: Prefix.
        :param config: Any key-value pairs added are stored as config.
        :raises: HandleSyntaxError
        '''
        util.check_handle_syntax_with_index(username)
        self.__handle_server_url = handle_server_url
        self.__username = username
        self.__password = password
        self.__prefix = prefix
        self.__handleowner = handleowner
        self.__config = None
        if len(config) > 0:
            self.__config = config

        if handleowner is not None:
            util.check_handle_syntax_with_index(handleowner)
            self.__handleowner = handleowner

    def get_username(self):
        # pylint: disable=missing-docstring
        return self.__username

    def get_password(self):
        # pylint: disable=missing-docstring
        return self.__password

    def get_server_URL(self):
        # pylint: disable=missing-docstring
        return self.__handle_server_url

    def get_prefix(self):
        # pylint: disable=missing-docstring
        return self.__prefix

    def get_handleowner(self):
        # pylint: disable=missing-docstring
        return self.__handleowner

    def get_config(self):
        # pylint: disable=missing-docstring
        return self.__config
