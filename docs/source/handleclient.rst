===========================
Handle Client documentation
===========================

.. important:: If you encounter security warnings when using the library, contact your Handle server administrators and ask them to set up the server certificates correctly! (see :doc:`handleserverconfig`)

The EUDATHandleClient class provides a Python-level interface for interactions with a Handle server through its native REST interface. The class provides common methods for working with Handles and their records:

* Create and modify Handles
* Search across Handles (using an additional servlet)
* Manage multiple URLs through special 10320/loc entries


General usage
=============

First, you create an instance of the client. It holds all necessary information, such as from which handle server to read, which
user credentials to use etc. Several different instantiation methods are available for different usages (see below).

  .. code:: python

    client = EUDATHandleClient.instantiate_...(...)


Then, use the client's methods to read, create and modify handles.

  .. code:: python

    value = client.some_method(...)

Search functionality is not offered by the Handle System. For searching, you need access to a customized search servlet.


Instantiation
=============

Before reading or modifying handles, you need to instantiate the client. The client class offers several constructors with differences in
the permissions and thus possible actions on the Handle server. 
Aside from the default constructor :meth:`~b2handle.handleclient.EUDATHandleClient.__init__`, there are several shorthand constructors: 

:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_for_read_access`
  Anonymous read-only access, no credentials needed, no search capabilities. Handles are read from the global Handle Registry.
:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_for_read_and_search`
  Read-only access, credentials for search functions required.
:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_with_username_and_password`
  Full read and write access, credentials required (username and password).
:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_with_credentials`
  Full read and write access, credentials required (username and password or client certificates). Credentials can conveniently be loaded from a JSON file. For this, please see documentation of :mod:`~b2handle.cliencredentials`.

On top of the required arguments, more arguments can be passed to the constructors as key-value pairs. Please see the documentation of
the default constructor to find out which values are understood.
 
  
Authentication
==============
 
For creating and modifying handles* you need to authenticate at the Handle Server you'd like to write to. Authentication using b2handle is straightforward. There are two possibilities:
 
* Authenticating using username and password
* Authenticating using client certificates

.. important:: Here we assume that you know your username and password or have your private key file and your certificate file ready. If you need to set these up, please see :doc:`authentication`.

Authentication using client certificates
----------------------------------------

Using client certificates, you need to provide paths to the file containing your private key and to the certificate in a JSON file. The class :class:`~b2handle.cliencredentials.PIDClientCredentials` provides a method :meth:`~b2handle.cliencredentials.PIDClientCredentials.load_from_JSON`. This can be read as follows:

  .. code:: python

    cred = PIDClientCredentials.load_from_JSON('my_credentials.json')
    client = EUDATHandleClient.instantiate_with_credentials(cred)
 
The JSON file should look like this:

  .. code:: json

    {
      "baseuri": "https://my.handle.server",
      "private_key": "my_private_key.pem",
      "certificate_only": "my_certificate.pem"
    }

Authentication using username and password
------------------------------------------
 
If you have a username (something that looks like **300:foo/bar**) and a password, we recommend using this constructor: :meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_with_username_and_password`:

  .. code:: python

    client = EUDATHandleClient.instantiate_with_username_and_password(
      'https://my.handle.server',
      '300:foo/bar',
      'mypassword123'
    )
 
Alternatively, you can store your username and password in a JSON file, instead of paths to certificate and key::
  {
  "baseuri": "https://my.handle.server",
  "username": "300:foo/bar",
  "password": "mypassword123"
  }

Like above, you can read the JSON like as shown above:

  .. code:: python

    cred = PIDClientCredentials.load_from_JSON('my_credentials.json')
    client = EUDATHandleClient.instantiate_with_credentials(cred)
 

Credentials JSON file
---------------------

The JSON file can contain more information. All items it contains are passed to the client constructor as config. Please see :meth:`~b2handle.handleclient.EUDATHandleClient.__init__` to find out which configuration items the client constructor understands.
 

  
Basic Handle interaction
========================

Creating a Handle
  Use :meth:`~b2handle.handleclient.EUDATHandleClient.register_handle` to create a Handle with a custom name or :meth:`~b2handle.handleclient.EUDATHandleClient.generate_and_register_handle` to create a Handle with a random UUID-based name. 

Deleting a Handle
  Use :meth:`~b2handle.handleclient.EUDATHandleClient.delete_handle`.  

Retrieving a full Handle record
  This can be done either through :meth:`~b2handle.handleclient.EUDATHandleClient.retrieve_handle_record` or :meth:`~b2handle.handleclient.EUDATHandleClient.retrieve_handle_record_json`.

Retrieving a single value
  Use :meth:`~b2handle.handleclient.EUDATHandleClient.get_value_from_handle` to retrieve a single Handle record value.  

Modifying a Handle record
  Use :meth:`~b2handle.handleclient.EUDATHandleClient.modify_handle_value` to modify any number of values in a specific Handle record. To remove individual values, use :meth:`~b2handle.handleclient.EUDATHandleClient.delete_handle_value`.

Searching for a Handle
  Use :meth:`~b2handle.handleclient.EUDATHandleClient.search_handle` to search for Handles with a specific key and value.
  Please note that searching requires access to a search servlet whose access information, if it differs from the handle server,
  has to be specified at client instantiation.


Managing multiple URLs with 10320/loc
=====================================

The client class offers several methods to adequately manage multiple URLs in a single Handle record. The Handle System mechanism used for this are entries with type *10320/loc*.
Use :meth:`~b2handle.handleclient.EUDATHandleClient.add_additional_URL`, :meth:`~b2handle.handleclient.EUDATHandleClient.exchange_additional_URL` and :meth:`~b2handle.handleclient.EUDATHandleClient.remove_additional_URL` to manage such entries.

In addition to these basic management methods, there are also two helper methods. Use :meth:`~b2handle.handleclient.EUDATHandleClient.is_10320LOC_empty` to check whether a Handle already contains a 10320/loc entry and :meth:`~b2handle.handleclient.EUDATHandleClient.is_URL_contained_in_10320LOC` to check whether a given URL is already present in a record.


Full method documentation
=========================
  
Constructors
------------

.. automethod:: b2handle.handleclient.EUDATHandleClient.__init__

.. automethod:: b2handle.handleclient.EUDATHandleClient.instantiate_for_read_access

.. automethod:: b2handle.handleclient.EUDATHandleClient.instantiate_for_read_and_search

.. automethod:: b2handle.handleclient.EUDATHandleClient.instantiate_with_username_and_password

.. automethod:: b2handle.handleclient.EUDATHandleClient.instantiate_with_credentials

Handle record methods
---------------------

.. automethod:: b2handle.handleclient.EUDATHandleClient.register_handle

.. automethod:: b2handle.handleclient.EUDATHandleClient.generate_and_register_handle

.. automethod:: b2handle.handleclient.EUDATHandleClient.delete_handle

.. automethod:: b2handle.handleclient.EUDATHandleClient.retrieve_handle_record

.. automethod:: b2handle.handleclient.EUDATHandleClient.retrieve_handle_record_json

.. automethod:: b2handle.handleclient.EUDATHandleClient.get_value_from_handle

.. automethod:: b2handle.handleclient.EUDATHandleClient.modify_handle_value

.. automethod:: b2handle.handleclient.EUDATHandleClient.delete_handle_value

.. automethod:: b2handle.handleclient.EUDATHandleClient.search_handle

Methods for managing 10320/loc entries
--------------------------------------

.. automethod:: b2handle.handleclient.EUDATHandleClient.add_additional_URL

.. automethod:: b2handle.handleclient.EUDATHandleClient.exchange_additional_URL

.. automethod:: b2handle.handleclient.EUDATHandleClient.remove_additional_URL

.. automethod:: b2handle.handleclient.EUDATHandleClient.is_10320LOC_empty

.. automethod:: b2handle.handleclient.EUDATHandleClient.is_URL_contained_in_10320LOC

Helper methods
--------------

.. automethod:: b2handle.handleclient.EUDATHandleClient.generate_PID_name
.. automethod:: b2handle.handleclient.EUDATHandleClient.get_handlerecord_indices_for_key


Utilities
==========

.. automodule:: b2handle.utilhandle
  :members:


Client credentials
==================

.. automodule:: b2handle.clientcredentials

.. automethod:: b2handle.clientcredentials.PIDClientCredentials.load_from_JSON
.. automethod:: b2handle.clientcredentials.PIDClientCredentials.__init__



Exceptions
==========

.. automodule:: b2handle.handleexceptions
  :members:


