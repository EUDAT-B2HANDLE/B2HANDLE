import unittest
from b2handle.handleclient import EUDATHandleClient
import json

class EUDATHandleClient_API_readaccess_faked_test(unittest.TestCase):

    def setUp(self):
        self.inst = EUDATHandleClient()
        self.handlerecord_json = {
            "responseCode":"1",
            "handle":"testprefix/testhandle",
            "values":
            [
                {
                    "index":111,
                    "type":"URL",
                    "data": {
                        "format":"string",
                        "value":"www.url.foo"
                    }
                },
                {
                    "index":222,
                    "type":"testtype",
                    "data":{
                        "format":"string",
                        "value":"testvalue"
                    }
                },
                {
                    "index":333,
                    "type":"testtype_duplicate",
                    "data":{
                        "format":"string",
                        "value":"testvalue"
                    }
                },
                {
                    "index":444,
                    "type":"testtype_duplicate",
                    "data":{
                        "format":"string",
                        "value":"testvalue"
                    }
                },
            ]
        }

    def get_value_from_handle_test(self):
        val = self.inst.get_value_from_handle('testprefix/testhandle', 'testtype', self.handlerecord_json)
        assert val == 'testvalue'

    def retrieve_handle_record_test(self):
        record_dict = self.inst.retrieve_handle_record('testprefix/testhandle', self.handlerecord_json)
        print 'The handle record as dict: '+str(record_dict)
        assert record_dict['testtype'] == 'testvalue'
        assert len(record_dict) == 3
        # The duplicate is ignored!

    def get_indices_for_key_test(self):

        indices = self.inst.get_handlerecord_indices_for_key('testtype', self.handlerecord_json['values'])
        assert len(indices) == 1
        assert indices[0] == 222
        indices = self.inst.get_handlerecord_indices_for_key('testtype_duplicate', self.handlerecord_json['values'])
        assert len(indices) == 2
        assert indices[0] == 333
        assert indices[1] == 444

class EUDATHandleClient_10320loc_readaccess_faked_test(unittest.TestCase):

    def setUp(self):
        self.inst = EUDATHandleClient()
        self.testhandle1 = '123456/testhandle1'
        self.testhandle2 = '123456/testhandle2'
        self.testhandleresponsecontent1 = r'{"responseCode":1, "handle":"123456/testhandle1", "values":[{"index":100, "type":"HS_ADMIN", "data":{"format":"admin", "value":{"handle":"0.NA/10876.TEST", "index":200, "permissions":"011111110011"}}, "ttl":86400, "timestamp":"2015-06-09T12:34:06Z"}, {"index":2, "type":"10320/loc", "data":{"format":"string", "value":"<locations chooseby = \"locatt,weighted\">\n<location weight = \"1\" href = \"http://foo.bar\" />\n<location http_role = \"conneg\" weight = \"0\" href = \"http://foo.foo\" />\n<location http_role = \"no_conneg\" weight = \"0\" href = \"http://clipc-services.ceda.ac.uk/testdata/v1/novar_fx_dummy_historical_r5i1p1_CHECKCONNEG.nc\" />\n</locations> "}, "ttl":86400, "timestamp":"2015-06-16T08:08:31Z"}, {"index":3, "type":"creation_date", "data":{"format":"string", "value":"2015-05-01"}, "ttl":86400, "timestamp":"2015-06-10T11:54:35Z"}, {"index":4, "type":"tracking_id", "data":{"format":"string", "value":"f05e5f1e-f011-11e4-8220-5404a60d96b5"}, "ttl":86400, "timestamp":"2015-06-10T11:54:41Z"}, {"index":5, "type":"replaced_by", "data":{"format":"string", "value":"10876.test/f0615066-f011-11e4-8220-5404a60d96b5"}, "ttl":86400, "timestamp":"2015-06-10T11:54:49Z"}, {"index":6, "type":"checksum", "data":{"format":"string", "value":"eb21b9cfbbcf223c0a012903c43fe7ad"}, "ttl":86400, "timestamp":"2015-06-09T12:34:53Z"}, {"index":7, "type":"parent", "data":{"format":"string", "value":"10876.test/49634b69-6662-4a52-9175-45f296dc9578"}, "ttl":86400, "timestamp":"2015-06-10T11:54:56Z"}, {"index":8, "type":"aggregation_level", "data":{"format":"string", "value":"file"}, "ttl":86400, "timestamp":"2015-06-10T11:55:14Z"}]}'
        self.testhandleresponsecontent2 = r'{"responseCode":1, "handle":"123456/testhandle2", "values":[{"index":100, "type":"HS_ADMIN", "data":{"format":"admin", "value":{"handle":"0.NA/10876.TEST", "index":200, "permissions":"011111110011"}}, "ttl":86400, "timestamp":"2015-06-09T12:34:06Z"}, {"index":3, "type":"creation_date", "data":{"format":"string", "value":"2015-05-01"}, "ttl":86400, "timestamp":"2015-06-10T11:54:35Z"}, {"index":4, "type":"tracking_id", "data":{"format":"string", "value":"f05e5f1e-f011-11e4-8220-5404a60d96b5"}, "ttl":86400, "timestamp":"2015-06-10T11:54:41Z"}, {"index":5, "type":"replaced_by", "data":{"format":"string", "value":"10876.test/f0615066-f011-11e4-8220-5404a60d96b5"}, "ttl":86400, "timestamp":"2015-06-10T11:54:49Z"}, {"index":6, "type":"checksum", "data":{"format":"string", "value":"eb21b9cfbbcf223c0a012903c43fe7ad"}, "ttl":86400, "timestamp":"2015-06-09T12:34:53Z"}, {"index":7, "type":"parent", "data":{"format":"string", "value":"10876.test/49634b69-6662-4a52-9175-45f296dc9578"}, "ttl":86400, "timestamp":"2015-06-10T11:54:56Z"}, {"index":8, "type":"aggregation_level", "data":{"format":"string", "value":"file"}, "ttl":86400, "timestamp":"2015-06-10T11:55:14Z"}]}'

        self.handlerecord1 = {
            "responseCode":1,
            "handle":self.testhandle1,
            "values": [
                {
                    "index":100,
                    "type":"HS_ADMIN",
                    "data":{"format":"admin", "value":{"handle":"0.NA/10876.TEST", "index":200, "permissions":"011111110011"}}, "ttl":86400, "timestamp":"2015-06-09T12:34:06Z"
                }, {
                    "index":2,
                    "type":"10320/loc",
                    "data":{"format":"string", "value":"<locations chooseby = \"locatt,weighted\">\n<location weight = \"1\" href = \"http://foo.bar\" />\n<location http_role = \"conneg\" weight = \"0\" href = \"http://foo.foo\" />\n<location http_role = \"no_conneg\" weight = \"0\" href = \"http://clipc-services.ceda.ac.uk/testdata/v1/novar_fx_dummy_historical_r5i1p1_CHECKCONNEG.nc\" />\n</locations> "}, "ttl":86400, "timestamp":"2015-06-16T08:08:31Z"
                }, {
                    "index":3,
                    "type":"creation_date",
                    "data":{"format":"string", "value":"2015-05-01"}, "ttl":86400, "timestamp":"2015-06-10T11:54:35Z"
                }, {
                    "index":4,
                    "type":"tracking_id",
                    "data":{"format":"string", "value":"f05e5f1e-f011-11e4-8220-5404a60d96b5"}, "ttl":86400, "timestamp":"2015-06-10T11:54:41Z"
                }, {
                    "index":5,
                    "type":"replaced_by",
                    "data":{"format":"string", "value":"10876.test/f0615066-f011-11e4-8220-5404a60d96b5"}, "ttl":86400, "timestamp":"2015-06-10T11:54:49Z"
                }, {
                    "index":6,
                    "type":"checksum",
                    "data":{"format":"string", "value":"eb21b9cfbbcf223c0a012903c43fe7ad"}, "ttl":86400, "timestamp":"2015-06-09T12:34:53Z"
                }, {
                    "index":7,
                    "type":"parent",
                    "data":{"format":"string", "value":"10876.test/49634b69-6662-4a52-9175-45f296dc9578"}, "ttl":86400, "timestamp":"2015-06-10T11:54:56Z"
                }, {
                    "index":8,
                    "type":"aggregation_level",
                    "data":{"format":"string", "value":"file"}, "ttl":86400, "timestamp":"2015-06-10T11:55:14Z"
                }
            ]
        }

    if True:
        def is_10320loc_empty_test(self):
            handle = self.testhandle1
            rec_json = self.handlerecord1
            # Contains a full 10320loc:
            answer1 = self.inst.is_10320loc_empty(handle, rec_json)
            print str(answer1)
            assert answer1 == False
            # Contains no 10320loc at all:
            del rec_json['values'][1]
            answer2 = self.inst.is_10320loc_empty(handle, rec_json)
            assert answer2 == True

    if True:
        def is_URL_contained_in_10320loc_test(self):
            json1 = json.loads(self.testhandleresponsecontent1)
            json2 = json.loads(self.testhandleresponsecontent2)
            answer1a = self.inst.is_URL_contained_in_10320loc(self.testhandle1, 'http://foo.bar', json1)
            assert answer1a == True
            answer1b = self.inst.is_URL_contained_in_10320loc(self.testhandle1, 'http://bar.bar', json1)
            assert answer1b == False
            answer2 = self.inst.is_URL_contained_in_10320loc(self.testhandle2, 'http://whatever.foo', json2)
            assert answer2 == False
