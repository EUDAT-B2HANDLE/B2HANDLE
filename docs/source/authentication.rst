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

The handle server admin has to add the ``HS_SECKEY`` entry with the user's password to an existing handle (e.g. '<prefix>/allusers') or create a new handle for this purpose (e.g. '<prefix>/johndoe'. He or she also has to grant write permissions to the user (see below).


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

The handle server admin has to add the ``HS_PUBKEY`` entry with the user's public key to an existing handle or create a new handle for this purpose.  He or she also has to grant write permissions to the user (see below).

For creating the certificate, the following steps may be required:

Creating the client certificate
-------------------------------

1. Creating a private/public key pair:

  * For this, you can use the command line tool "hdl-keygen" that is shipped together with the handle system software:

    .. code:: json
    
      bash /.../handlesystem_software/hsj-8.x.x/bin/hdl-keygen 
                    -alg dsa
                    -keysize 2048 
                     301_foo_bar_privkey.bin 301_foo_bar_pubkey.bin
    
    Note: We put 301_foo_bar into the name to remember for which username this keypair is generated!

  * When it asks whether you want to encrypt the key, type 'n':

      .. code:: json
  
        Would you like to encrypt your private key? (y/n) [y] n

    Why? The b2handle library uses the python library *requests* which does not support encrypted private keys:
    *"The private key to your local certificate must be unencrypted. Currently, requests does not support 
    using encrypted keys."* (see `requests documentation on this topic <http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification>`__).

2. Upload the user's public key to the ``HS_PUBKEY`` entry:

  * For this, you can use the command line tool "hdl-admintool" that is shipped together with the handle system software:

      .. code:: json
  
        bash /.../handlesystem_software/hsj-8.x.x/bin/hdl-admintool
  
  * Authenticate with your handle-server-admin credentials
  * Lookup the handle where you want to store the user's public key (foo/bar)
  * "Edit"
  * "Add" > "Blank Value"
  * Index: In this example, we use 301. As a convention, take the lowest value >= 301 that is not in use yet.
  * "Load from file" > Choose the file "301_foo_bar_pubkey.bin"
  * The value type should have set itself to *"Hex"* now.
  * Don't forget to give admin permissions to the username 301:foo/bar, where you just uploaded the public key!

3. Transforming the binary private key (.bin) to a .pem file:

  * For this, you can use the command line tool "hdl-convert-key" that is shipped together with the handle system software:

      .. code:: json

        bash /.../handlesystem_software/hsj-8.x.x/bin/hdl-convert-key 
                                            /.../301_foo_bar_privkey.bin 
                                         -o /.../301_foo_bar_privkey.pem

4. Creating the certificate file:
  
  * This can be done using openssl:

      .. code:: json
  
        openssl req -pubkey -x509 -new  -key /.../301_foo_bar_privkey.pem 
                                        -out /.../301_certificate_and_publickey.pem -sha1
  
  * The tool is then going to prompt for some information. For the first 5 prompts, it does not matter what you enter- the entries are going to be ignored by the Handle Server.
    However, it is very important to enter the username as Common Name and *leave the Email address blank*, as it is going to be appended to the username otherwise. This will look like
    this:

    .. code-block:: none
       :emphasize-lines: 13,14

          You are about to be asked to enter information that will be incorporated
          into your certificate request.
          What you are about to enter is what is called a Distinguished Name or a DN.
          There are quite a few fields but you can leave some blank
          For some fields there will be a default value,
          If you enter '.', the field will be left blank.
          -----
          Country Name (2 letter code) [XX]:
          State or Province Name (full name) []:
          Locality Name (eg, city) [Default City]:
          Organization Name (eg, company) [Default Company Ltd]:
          Organizational Unit Name (eg, section) []:
          Common Name (eg, your name or your server's hostname) []:300:foo/bar
          Email Address []:

5. Optional: Removing the public key from the certificate file:

    .. code:: json
    
      openssl x509 -inform PEM -in /.../301_certificate_and_publickey.pem
                               -out /.../301_certificate_only.pem

Now, the certificate_only.pem file and the private_key.pem file can be used for authentication.
The paths to these files should be entered into the JSON credentials file asfollows::

  {
    "handle_server_url": "https://my.handle.server",
    "private_key": "301_foo_bar_privkey.pem",
    "certificate_only": "301_certificate_only.pem"
  }

Please follow the client documentation to see how a user can use this JSON file to authenticate while using the b2handle library.


Giving admin permissions to users
=================================

No matter which of the methods is used, in both cases the Handle Server admin (or prefix owner) has to give write permissions to
the user. The admin can do that in several ways. Note that while the third method looks most complex, it may be the easiest one,
as it is most easily modified and extended (without having to contact the prefix provider to changes in the **0.NA/foo** record).

These are three ways to grant admin permissions to users **300:foo/bar** and **301:foo/bar**:

1.  By creating a ``HS_ADMIN`` entry for each username in the prefix owner handle record (i.e. somewhere in the record **0.NA/foo**).

    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    100   HS_ADMIN  (refers to 300:foo/bar)
    101   HS_ADMIN  (refers to 301:foo/bar)
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= ==========
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= ==========

2. By adding the usernames (**300:foo/bar** and **301:foo/bar**) to a ``HS_VLIST`` entry in the prefix owner handle record
   (i.e. somewhere in the record **0.NA/foo**), which was referenced in a ``HS_ADMIN`` entry in **0.NA/foo**.

    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    100   HS_ADMIN  (refers to 200:0.NA/foo)
    200   HS_VLIST  300:foo/bar
                    301:foo/bar
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= ==========
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= ==========

3. By adding the usernames (**300:foo/bar** and **301:foo/bar**) to any ``HS_VLIST`` entry referenced somewhere in **0.NA/foo**.
   For example, if there is a ``HS_ADMIN`` at index 101 of **0.NA/foo** which points to a ``HS_VLIST`` at the index 200 in 
   **0.NA/foo**, which points to a ``HS_VLIST`` at index 200 in 'foo/admin', which points to a ``HS_SECKEY`` at index 300 in 'foo/bar' - then **300:foo/bar** is a username with all the permissions stated in the ``HS_ADMIN`` entry at the index 101 of **0.NA/foo**.

    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    100   HS_ADMIN  (refers to 200:0.NA/foo)
    200   HS_VLIST  200:foo/bar
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    200   HS_VLIST  300:foo/bar
                    301:foo/bar
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= =======================

Common problems
===============

Some common problems when authenticating, together with possible solutions. Please note that the provided problem
causes are causes we observed. Of course it is possible that other reasons may cause the same problems, in that case
these solutions may not work.

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

  **Possible Solution:**

    Sometimes, this error occurs if the private key was encrypted. Please try with an unencrypted private key.
    This can occur with unencrypted keys, too. We have no proposed solution for that.

HTTP 401
--------

  **Problem:**

    * HTTP status code 401 (*Unauthorized*)
    * HS response code 402 (*Authentication needed*)
    * The handle server returns a JSON object that looks like this: ``{"responseCode":402,"handle":"myprefix/123456"}``

  **Possible Solution:**

    This error occurs if the client certificate was not correctly passed to the handle server. Possibly the server
    forwards the request internally to a different port and loses the certificate information on the way (e.g. using httpd ProxyPass).
    Please ask your handle server administrator about this. Testing the same request directly on the port of the handle server (if
    that is open for external access) can help finding out whether this is the problem.

SSL Error
---------

  **Problem:**

    ``requests.exceptions.SSLError: [SSL] PEM lib (_ssl.c:2525)``

  **Possible Solution:**

    This error occurs if the private key was not provided, for example if a single file instead of two was provided,
    but the private key was not contained. FOr this reason, we only recommend and describe passing certificate and
    private key in two separate files.
