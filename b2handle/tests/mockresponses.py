import json
import mock
'''
Mock Request and Response objects needed for many tests.
'''

class MockRequest(object):
    '''
    This is a mocked Request object containing only an url,
    as this is the only attribute accessed during the tests.
    There is a default value for it, but it can also be passed.
    '''
    def __init__(self, url=None):
        if url is not None:
            self.url = url
        else:
            self.url = 'http://foo.foo'
    
class MockResponse(object):
    '''
    This is a mocked Response object (can be used to replace
    a response from any call to "requests.get" or
    "request.put" or "request.delete", ...).

    It contains a request, a status code and some JSON content.
    For all of these, there is default values, but they can also
    be passed.

    Some standard cases are available, e.g. or "handle not found",
    which has a specific combination of HTTP status code, handle
    response code and content.
    '''
    def __init__(self, status_code=None, content=None, request=None, success=False, notfound=False, empty=False, wascreated=False):

        self.content = None
        self.status_code = None
        self.request = None

        # Some predefined cases:
        if success:
            self.status_code = 200
            self.content = '{"responseCode":1, "handle":"my/testhandle"}'
        elif notfound:
            self.status_code = 404
            self.content = '{"responseCode":100}'
        elif empty:
            self.status_code = 200
            self.content = '{"responseCode":200}'
        elif wascreated:
            self.status_code = 201
            self.content = '{"responseCode":1, "handle":"my/testhandle"}'
        # User-defined overrides predefined cases:
        if content is not None:
            self.content = content
        if status_code is not None:
            self.status_code = status_code
        if request is not None:
            self.request = request
        # Defaults (they do not override):
        if self.content is None:    
            self.content = '{"responseCode":1}'
        if self.status_code is None:
            self.status_code = 200
        if self.request is None:
            self.request = MockRequest()


class MockSearchResponse(object):
    '''
    This is a mocked Response object for search servlet.
    '''
    def __init__(self, status_code=None, content=None, request=None, success=False, wrong_url=False, undefined_field=False, auth_fail=False, handle_url=False, empty=False, prefix=None):

        self.content = None
        self.status_code = None
        self.request = None
        beta2=True # which HSv8 version should be mocked?
        beta1=False
        solr=False # Is a solr queried or a database?

        # Some predefined cases:
        if success:
            self.status_code = 200
            self.content = json.dumps(["prefix/suffix", "prefix2/suffix2", "prefix2/suffix2b"])
        elif empty:
            self.status_code = 200
            self.content = json.dumps([])
        elif undefined_field:
            if solr:
                self.status_code = 9999999 # TODO
                self.content = 'RemoteSolrException: Error from server at .+: undefined field FooBar' # TODO
        elif auth_fail:
            self.status_code = 401
        elif wrong_url:
            self.request = MockRequest()
            self.status_code = 404
            self.content = '<!DOCTYPE html>...'
        elif handle_url:
            self.request = MockRequest()
            self.status_code = 404
            if beta1:
                self.content = 'The handle you requested.+cannot be found'
            if beta2:
                self.content = {"responseCode":102, "message":"Empty handle invalid"}
        # User-defined overrides predefined cases:
        if content is not None:
            self.content = content
        if status_code is not None:
            self.status_code = status_code
        if request is not None:
            self.request = request
        # Defaults (they do not override):
        if self.content is None:    
            self.content = '[]'
        if self.status_code is None:
            self.status_code = 200
        if self.request is None:
            self.request = MockRequest()

class MockCredentials(object):
    '''
    This is a mocked credentials object.
    '''
    def __init__(self,
        config=None,
        user=None,
        password=None,
        url=None,
        restapi=None,
        handleowner=None,
        private_key=None,
        certificate_and_key=None,
        certificate_only=None,
        prefix=None
    ):

        self.config = config

        if restapi is not None:
            self.config = {}
            self.config['REST_API_url_extension'] = restapi

        self.user = '100:my/testhandle'
        if user is not None:
            self.user = user

        self.key = private_key
        self.cert = certificate_only
        self.cert_and_key = certificate_and_key

        self.password = 'password123abc'
        if password is not None:
            self.password = password

        self.url='http://some/url'
        if url is not None:
            self.url = url

        if handleowner is not None:
            self.handleowner = handleowner
        else:
            self.handleowner = self.user

        self.prefix=prefix

        self.all_config = {}
        self.all_config.update(self.config)
        self.all_config['username'] = self.user
        self.all_config['password'] = self.password
        self.all_config['handleowner'] = self.handleowner
        self.all_config['handle_server_url'] = self.url
        self.all_config['private_key'] = self.key
        self.all_config['certificate_only'] = self.cert
        self.all_config['certificate_and_key'] = self.cert_and_key
        self.all_config['prefix'] = self.prefix


        self.get_config = mock.MagicMock(return_value=self.config)
        self.get_username = mock.MagicMock(return_value=self.user)
        self.get_password = mock.MagicMock(return_value=self.password)
        self.get_server_URL = mock.MagicMock(return_value=self.url)
        self.get_handleowner = mock.MagicMock(return_value=self.handleowner)
        self.get_path_to_private_key = mock.MagicMock(return_value=self.key)
        self.get_path_to_file_certificate_only = mock.MagicMock(return_value=self.cert)
        self.get_path_to_file_certificate_and_key = mock.MagicMock(return_value=self.cert_and_key)
        self.get_all_args = mock.MagicMock(return_value=self.all_config)