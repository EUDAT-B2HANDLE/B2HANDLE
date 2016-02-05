'''
Created on 2015-07-02
Started implementing 2015-07-15
Last updated: 2015-08-26
'''

from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import CredentialsFormatError
import util
import json
import os

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
        if 'baseuri' in jsonfilecontent:
            jsonfilecontent['handle_server_url'] = jsonfilecontent['baseuri']
            del jsonfilecontent['baseuri']
        instance = PIDClientCredentials(**jsonfilecontent)
        return instance


    def __init__(self, **args):
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
        # Possible arguments:
        useful_args = ['handle_server_url', 'username', 'password', 'private_key', 'certificate_only','certificate_and_key', 'prefix', 'handleowner']
        util.add_missing_optional_args_with_value_none(args, useful_args)

        # Args that the constructor understands:
        self.__handle_server_url = args['handle_server_url']
        self.__username = args['username']
        self.__password = args['password']
        self.__prefix = args['prefix']
        self.__handleowner = args['handleowner']
        self.__private_key = args['private_key']
        self.__certificate_only = args['certificate_only']
        self.__certificate_and_key = args['certificate_and_key']

        # Other attributes:
        self.__additional_config = None

        # All the other args collected as "additional config":
        self.__additional_config = self.__collect_additional_arguments(args, useful_args)

        # Some checks:
        self.__check_mandatory_args()
        self.__check_handle_syntax()
        self.__check_file_existence()
        self.__check_if_enough_arguments_for_authentication()

    def __collect_additional_arguments(self, args, used_args):
        temp_additional_config = {}
        for argname in args.keys():
            if argname not in used_args:
                temp_additional_config[argname] = args[argname]
        if len(temp_additional_config) > 0:
            return temp_additional_config
        else:
            return None

    def __check_mandatory_args(self):
        if self.__handle_server_url is None:
            raise CredentialsFormatError(msg='The Handle Server\'s URL is missing in the credentials.')

    def __check_handle_syntax(self):
        if self.__handleowner:
            util.check_handle_syntax_with_index(self.__handleowner)
        if self.__username:
            util.check_handle_syntax_with_index(self.__username)

    def __check_file_existence(self):
        if self.__certificate_only:
            if not os.path.isfile(self.__certificate_only):
                msg = 'The certificate file was not found at the specified path: '+self.__certificate_only
                raise CredentialsFormatError(msg=msg)
        if self.__certificate_and_key:
            if not os.path.isfile(self.__certificate_and_key):
                msg = 'The certificate file was not found at the specified path: '+self.__certificate_and_key
                raise CredentialsFormatError(msg=msg)
        if self.__private_key:
            if not os.path.isfile(self.__private_key):
                msg = 'The private key file was not found at the specified path: '+self.__private_key
                raise CredentialsFormatError(msg=msg)

    def __check_if_enough_arguments_for_authentication(self):

        # Which authentication method?
        authentication_method = None

        # Username and Password
        if self.__username and self.__password:
            authentication_method = 'user_password'

        # Certificate file and Key file
        if self.__certificate_only and self.__private_key:
            authentication_method = 'auth_cert_2files'

        # Certificate and Key in one file
        if self.__certificate_and_key:
            authentication_method = 'auth_cert_1file'

        # None was provided:
        if authentication_method is None:
            msg = ''
            if self.__username and not self.__password:
                msg += 'Username was provided, but no password. '
            elif self.__password and not self.__username:
                msg += 'Password was provided, but no username. '
            if self.__certificate_only and not self.__private_key:
                msg += 'A client certificate was provided, but no private key. '
            elif self.__private_key and not self.__certificate_only:
                msg += 'A private key was provided, but no client certificate. '
            raise CredentialsFormatError(msg=msg)


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
        return self.__additional_config

    def get_path_to_private_key(self):
        # pylint: disable=missing-docstring
        return self.__private_key

    def get_path_to_file_certificate(self):
        # pylint: disable=missing-docstring
        return self.__certificate_only or self.__certificate_and_key

    def get_path_to_file_certificate_only(self):
        # pylint: disable=missing-docstring
        return self.__certificate_only

    def get_path_to_file_certificate_and_key(self):
        # pylint: disable=missing-docstring
        return self.__certificate_and_key