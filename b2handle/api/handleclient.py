'''
Created on 2015-07-02
'''

    
class EUDATHandleClient(object):
    """
    B2Handle main client class.
    
    (formerly B2SAFE epic client)
    """
    
    def __init__(self, handle_server_url="https://hdl.handle.net"):
        """
        Initialize the client in read-only mode. Access is anonymous, thus no credentials are required.

        :param handle_server_url: Optional. The URL of the Handle System server to read from. Defaults to 'https://hdl.handle.net'
        """
    
    @staticmethod
    def instantiateWithUsernamePassword(handle_server_url, username, password):
        """
        Initialize client against an HSv8 instance with full read/write access.
        
        :param handle_server_url: The URL of the Handle System server.
        :param username: This must be a handle value reference in the format "index:prefix/suffix". The method will throw an exception upon bad syntax or non-existing Handle.
        :param password: This is the password stored as secret key in the actual Handle value the username points to.
        :raises: HandleNotFoundException: If the username handle is not found.
        :raises: HandleSyntaxError
        """

    @staticmethod
    def instantiateWithCredentials(credentials):
        """
        Initialize (and return) the client against an HSv8 instance with full read/write access.
        
        :param credentials: A credentials object, see separate class PIDClientCredentials.
        :raises: HandleNotFoundException: If the username handle is not found.
        :return: An instance of the client.   
        """

    def searchHandle(self, key, value, prefix=None):
        """
        Search for handles containing the specified key with the specified value.
        
        :param key: The key to search for. May be None.
        :param value: The value to search for.
        :param prefix: Optional. The Handle prefix to which the search should be limited to. If unspecified, the method will search across all prefixes present at the server given to the constructor.
        
        :return: A list of all Handles (strings) that bear the given key with given value of given prefix or server. The list may be empty and may also contain more than one element.
        """
        
    def retrieveHandleRecord(self, handle):
        """
        Retrieve a handle record from the Handle server.

        Parameters:
        :param handle: The handle whose record to retrieve.
        :return: A dict where the keys are keys from the Handle record (except HS_ADMIN) and every value is a string. The result will be None if the Handle does not exist.
        :raises: HandleSyntaxError.
        """
        
    def getValueFromHandle(self, handle, key):
        """
        Retrieve a single value from a single Handle. If several entries with this key exist, the methods returns the first one. If the handle does not exist, the method will raise a HandleNotFoundException.
        
        :param handle: The handle to take the value from.
        :param key: The key.
        :return: A string containing the value or None if the Handle record does not contain the key.
        :raises: HandleSyntaxError.
        :raises: HandleNotFoundException.
        """
        
    def registerHandle(self, handle, location, checksum=None, extratypes=None, additionalURLs=None, overwrite=False):
        """
        Registers a new Handle with given name. If the handle already exists and overwrite is not set to True, the method will throw an exception.
        
        :param handle: The full name of the handle to be registered (prefix and suffix)
        :param location: The URL of the data entity to be referenced
        :param checksum: Optional. The checksum string.
        :param extratypes: Optional. Additional key value pairs as dict.
        :param additionalURLs: Optional. A list of URLs (as strings) to be added to the handle record as 10320/loc entry.
        :param overwrite: Optional. If set to True, an existing handle record will be overwritten. Defaults to false.
        :raises: HandleAlreadyExistsException. Only if overwrite is not set or set to False.
        :raises: HandleAuthentificationError.
        :raises: HandleSyntaxError.
        :return: The handle name.
        """
       
    def generateAndRegisterHandle(self, prefix, location, checksum=None, extratypes=None, additionalURLs=None):
        """
        Registers a new Handle with a unique random name (random UUID).
        
        :param prefix: The prefix of the handle to be registered. The method will generate a suffix.
        :param location: The URL of the data entity to be referenced.
        :param checksum: Optional. The checksum string.
        :param extratypes: Optional. Additional key value pairs as dict.
        :param additionalURLs: Optional. A list of URLs (as strings) to be added to the handle record as 10320/loc entry.
        :raises: HandleAuthentificationError.
        :return: The new handle name.
        """

    def modifyHandleValue(self, handle, key, newvalue):
        """Modify an entry (key-value-pair) in a handle record. If the key does not exist yet, it is created.

        Parameters:
        :param handle: Handle whose record is to be modified
        :param key: The name of the handle value type to be changed
        :param value: New value to store in "data"
        :raises: HandleAuthentificationError.
        :raises: HandleNotFoundException.
        :raises: HandleSyntaxError.
        """

    def deleteHandleValue(self, handle, key):
        """Delete a key-value pair from a handle record. If the key exists more than once, all key-value pairs with this key are deleted.

        :param handle: Handle from whose record the entry should be deleted.
        :param key: Key to be deleted.
        :raises: HandleAuthentificationError.
        :raises: HandleNotFoundException.
        :raises: HandleSyntaxError.
        :return: True if the entry existed and was deleted; False if it did not exist (in this case the record did not change)
        """
        # IMPORTANT: Check if handle syntax is correct


    def deleteHandle(self, handle):
        """Delete the handle and its handle record.

        :param handle: Handle to be deleted.
        :raises: HandleAuthentificationError.
        :raises: HandleNotFoundException.
        :raises: HandleSyntaxError.
        """
        # IMPORTANT: Check if there is more than 1 parameter, then exception (user probably wanted to delete just a key-value pair!)
        # IMPORTANT: Check if handle syntax is correct


    def addAdditionalURL(self, handle, url):
        """
        Add a URL entry to the handle record's 10320/loc entry. If 10320/loc does not exist yet, it is created. If the 10320/loc entry already contains the URL,  it is not added a second time.

        :param handle: The handle to add the URL to.
        :param url: The URL to be added.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :raises: HandleAuthentificationError
        :return: True if the URL was added, False if it already existed (i.e. the handle record was not modified).
        """

    def removeAdditionalURL(self, handle, url):
        """
        Remove a URL from the handle record's 10320/loc entry.

        :param handle: The handle to modify.
        :param url: The URL to remove.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :raises: HandleAuthentificationError
        :return: True if the URL was removed from the 10320/loc entry; False if it did not exist (i.e. the handle record was not modified).
        """

    def isURLContainedIn10320loc(self, handle, url):
        """
        Checks if the URL is already present in the handle record's 10320/loc entry.

        :param handle: The handle.
        :param url: The URL.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :return: True if the handle record's 10320/loc entry contains the URL; False otherwise.
        """

    def is10320locEmpty(self, handle):
        """
        Checks if there is a 10320/loc entry in the handle record.

        :param handle: The handle.
        :raises: HandleNotFoundException
        :raises: HandleSyntaxError
        :return: True if the record contains a 10320/loc entry; False otherwise.
        """

    def dummy(self):
        """
        Return True (for testing purposes only)
        """
        return(True)

        
class PIDClientCredentials(object):
    """
    Provides authentication information to access a Handle server.

    """

    @staticmethod
    def loadFromJSON(json_filename):
        """
        Create a new instance of a PIDClientCredentials with information read from a local JSON file.

        :param json_filename: The path to the json credentials file. The json file should have the following format:
        {
            "baseuri": "https://url.to.your.handle.server",
            "username": "index:prefix/suffix",
            "password": "ZZZZZZZ"
        }
        :raises: CredentialsFormatError
        :raises: HandleSyntaxError
        :return: An instance.
        """
    
    def __init__(handle_server_url, username, password):
        """
        Initialize client credentials instance with Handle server url, username and password.

        :param handle_server_url: URL to your handle server 
        :param username: User information in the format "index:prefix/suffix"
        :param password: Password.
        :raises: HandleSyntaxError
        """
