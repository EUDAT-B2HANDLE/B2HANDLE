===========================
Handle Client documentation
===========================

.. important:: Before using the library, make sure you have configured your Handle server correctly! (see :doc:`handleserverconfig`)

The EUDATHandleClient class provides a Python-level interface for interactions with a Handle server through its native REST interface. The class provides common methods for working with Handles and their records:

* Create and modify Handles
* Search across Handles (using an additional servlet)
* Manage multiple URLs through special 10320/loc entries

Instantiation
=============

The client class offers several constructors with differences in the permissions and thus possible actions on the Handle server. 
Aside from the default constructor :meth:`~b2handle.handleclient.EUDATHandleClient.__init__`, there are several shorthand constructors: 

:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_for_read_access`
  Anonymous read-only access, no credentials needed, no search capabilities.
:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_for_read_and_search`
  Read-only access, credentials for search functions required.
:meth:`~b2handle.handleclient.EUDATHandleClient.instantiate_with_username_and_password`
  Full read and write access, credentials required.
  
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
.. automethod:: b2handle.handleclient.EUDATHandleClient.make_handle_URL
.. automethod:: b2handle.handleclient.EUDATHandleClient.check_handle_syntax
.. automethod:: b2handle.handleclient.EUDATHandleClient.check_handle_syntax_with_index
.. automethod:: b2handle.handleclient.EUDATHandleClient.remove_index
.. automethod:: b2handle.handleclient.EUDATHandleClient.get_handlerecord_indices_for_key
.. automethod:: b2handle.handleclient.EUDATHandleClient.create_authentication_string
.. automethod:: b2handle.handleclient.EUDATHandleClient.check_if_username_exists
.. automethod:: b2handle.handleclient.EUDATHandleClient.create_revlookup_query

Exceptions
==========

.. automodule:: b2handle.handleexceptions
  :members:


