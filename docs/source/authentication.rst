=================================
Authentication at a Handle Server
=================================

Below, we describe the two methods to authenticate at a Handle Server for write access.
In both methods, the library user has a username of this form: **index:prefix/suffix**.

It does not only look like a handle, it is a handle - it points to an entry in a handle
where the information needed to verify the user's identity are stored.

.. important:: The user, identified by his username, needs to be granted write permissions
  by the handle server admin. For this, please see below.


Using username and password
===========================

Authenticating via username and password means that the password has to be stored as a ``HS_SECKEY`` entry in the record of a handle (this entry is, of course, hidden and not visible to the public!). This handle, together with the index of the ``HS_SECKEY`` entry, is the username.

For example, in the handle record of handle 'foo/bar', there is a ``HS_SECKEY`` entry with the value 'mypassword' at index 300. Then, the username is **300:foo/bar** and the password is 'mypassword':

===== ========= ==========
Index Key       Value
 ...  ...       ...
300   HS_SECKEY mypassword
 ...  ...       ...
===== ========= ==========

The handle server admin has to add the ``HS_SECKEY`` entry with the user's password to an existing handle (e.g. '<prefix>/allusers') or create a new handle for this purpose (e.g. '<prefix>/johndoe'). He or she also has to grant write permissions to the user (see below).


Using client certificates
=========================

Authenticating via client certificate means that the user's public key has to be stored as a ``HS_PUBKEY`` entry in the record of a handle. This handle, together with the index of the ``HS_PUBKEY`` entry, is the username.

For example, in the handle record of handle 'foo/bar',there is a ``HS_PUBKEY`` entry with the user's public key (in a hex format) at index 301. Then, the username is '301:foo/bar'. Instead of a password, the user then needs to authenticate using his private key and a certificate containing this username.

===== ========= ==============
Index Key       Value
 ...  ...       ...
301   HS_PUBKEY 0000A552100...
 ...  ...       ...
===== ========= ==============

The handle server admin has to add the ``HS_PUBKEY`` entry with the user's public key to an existing handle or
create a new handle for this purpose. He or she also has to grant write permissions to the user
(see :ref:`givingpermissiontousers`.).

For creating the certificate, please follow these instructions: :ref:`creatingclientcertificate`.


Common problems
===============

Some common problems when authenticating, together with possible solutions. Please note that the provided problem
causes are causes we observed. Of course it is possible that other reasons may cause the same problems, in that case
these solutions may not work.

HTTP 401
--------

  **Problem:**

    * The handle server returns a JSON object that looks like this: ``{"responseCode":402,"handle":"myprefix/123456"}``
    * Handle Server responseCode 402 (*Authentication needed*)
    * HTTP status code 401 (*Unauthorized*)

  **Possible Solution:**

    This error occurs if the client certificate was not correctly passed to the handle server. Possibly the server
    forwards the request internally to a different port and loses the certificate information on the way (e.g. using httpd ProxyPass).
    Please ask your handle server administrator about this. Testing the same request directly on the port of the handle server (if
    that is open for external access) can help finding out whether this is the problem.

HTTP 403
--------

  **Problem:**

    * The handle server returns a JSON object that looks like this: ``{"responseCode":400,"handle":"myprefix/123456"}``
    * Handle Server responseCode: 400 (*Other authentication errors*)
    * HTTP status code 403 (*Forbidden*).

  **Possible solution 1:**
  
    This error occurs if the username does not have admin permissions yet. Make sure it is referred to in a
    HS_ADMIN or HS_VLIST that has admin permissions.

  **Possible solution 2:**
  
    This error also occurs if the username did not get permissions for this specific handle in its HS_ADMIN entry. Each user
    can only modify handles whose HS_ADMIN entry (or one of its HS_ADMIN entries) gives write permissions to him, either directly
    or by pointing to a HS_VLIST that has admin permissions and that contains the username.


Handshake Failure
-----------------

  **Problem:**

    ``SSL routines:SSL3_READ_BYTES:ssl handshake failure``


  **Possible Solution 1:**

    This error can occur if the private key was encrypted. Please try with an unencrypted private key.

  **Possible Solution 2:**

    Make sure that openssl version 1.0.1 or higher is used. Openssl 0.98 gives handshake errors.

SSL Error
---------

  **Problem:**

    ``requests.exceptions.SSLError: [SSL] PEM lib (_ssl.c:2525)``

  **Possible Solution:**

    This error occurs if the private key was not provided, for example if a single file instead of two was provided,
    but the private key was not contained. For this reason, we only recommend and describe passing certificate and
    private key in two separate files.

SSL Error
---------

  **Problem:**

    ``SSLError: SSL3_GET_SERVER_CERTIFICATE:certificate verify failed``

  **Possible Solution:**

    This error occurs if the server certificate at the handle server can not be verified at the client side. The library
    default is to verify the certificate. This is normally done with a certificate from a CA authority. The credentials
    file can have an optional parameter ``HTTPS_verify`` to change the behaviour. The problem can be solved in several ways.
    By adding the correct CA certificate to the bundle on the system. By setting a path to the correct CA certificate as follows:
    ``"HTTPS_verify": "/path_to_ca_certificate/ca_certificate"``. Or by disabling the checking of the certificate:
    ``"HTTPS_verify": "False"``. The last option is the least desired option.
