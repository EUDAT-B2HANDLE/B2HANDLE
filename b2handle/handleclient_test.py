import unittest
import handleclient

class EUDATHandleClient_test(unittest.TestCase):

    # So far, we only test if the module is loaded correctly and if the methods can be called using the defined signatures and (numbers of) arguments.

    def setUp(self):
        self.client = handleclient.EUDATHandleClient()

    def tearDown(self):
        pass

    def init_test_1(self):
        dummy = handleclient.EUDATHandleClient()

    def init_test_2(self):
        dummy = handleclient.EUDATHandleClient("https://hdl.handle.net")

    def init_test_3(self):
        dummy = handleclient.EUDATHandleClient("xyz")

    def instantiateWithUsernamePassword_test(self):
        dummy = handleclient.EUDATHandleClient.instantiateWithUsernamePassword("xyz", "userbla", "passwordbla")

    def instantiateWithCredentials_test(self):
        credentials = "this is a credentials object..."
        dummy = handleclient.EUDATHandleClient.instantiateWithCredentials(credentials)

    def dummy_test(self):
        dummyresult = self.client.dummy()
        assert dummyresult==True



        