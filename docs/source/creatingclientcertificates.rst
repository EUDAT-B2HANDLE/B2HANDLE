.. _creatingclientcertificate:

===============================
Creating the client certificate
===============================

For authentication using client certificates, a special pair of keys and a certificate file is required.
Follow these five steps to create them for your users:

1. :ref:`step1`.
2. :ref:`step2`.
3. :ref:`step3`.
4. :ref:`step4`.
5. :ref:`step5`.


.. _step1:

Creating a private/public key pair
==================================

  * For this, you can use the command line tool "hdl-keygen" that is shipped together with the handle system software:

    .. code:: json
    
      bash /.../handlesystem_software/hsj-8.x.x/bin/hdl-keygen 
                    -alg rsa
                    -keysize 4096 
                     301_foo_bar_privkey.bin 301_foo_bar_pubkey.bin
    
    Note: We put 301_foo_bar into the name to remember for which username this keypair is generated!

  * When it asks whether you want to encrypt the key, type 'n':

      .. code:: json
  
        Would you like to encrypt your private key? (y/n) [y] n

    Why? The b2handle library uses the python library *requests* which does not support encrypted private keys:
    *"The private key to your local certificate must be unencrypted. Currently, requests does not support 
    using encrypted keys."* (see `requests documentation on this topic <http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification>`__).


.. _step2:

Upload the user's public key to the ``HS_PUBKEY`` entry
=======================================================

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


.. _step3:

Transforming the binary private key (.bin) to a .pem file
=========================================================

  * For this, you can use the command line tool "hdl-convert-key" that is shipped together with the handle system software:

      .. code:: json

        bash /.../handlesystem_software/hsj-8.x.x/bin/hdl-convert-key 
                                            /.../301_foo_bar_privkey.bin 
                                         -o /.../301_foo_bar_privkey.pem

.. _step4:

Creating the certificate file
=============================
  
This can be done in 2 ways:
  
Case 1: Using openssl with specifying a subject.

      .. code:: json

        openssl req -pubkey -x509 -new -sha256 -subj "/CN=301:foo\/bar" -days 3652
                                        -key /.../301_foo_bar_privkey.pem 
                                        -out /.../301_certificate_and_publickey.pem

Done!

Case 2: Using openssl without specifying a subject:

      .. code:: json
  
        openssl req -pubkey -x509 -new  -key /.../301_foo_bar_privkey.pem -days 3652
                                        -out /.../301_certificate_and_publickey.pem -sha256




  
The tool is then going to prompt for some information if you do not specify a subject. For the first 5 prompts, it does not matter what you enter- the entries are going to be ignored by the Handle Server.

However, it is very important to enter the username as Common Name and *leave the Email address blank*, as it is going to be appended to the username otherwise. This will look like this:

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

Done!

.. _step5:

Removing the public key from the certificate file
=================================================

    .. code:: json
    
      openssl x509 -inform PEM -in /.../301_certificate_and_publickey.pem
                               -out /.../301_certificate_only.pem

Usage
=====

Now, the certificate_only.pem file and the private_key.pem file can be used for authentication.
The paths to these files should be entered into the JSON credentials file asfollows::

  {
    "handle_server_url": "https://my.handle.server",
    "private_key": "301_foo_bar_privkey.pem",
    "certificate_only": "301_certificate_only.pem"
  }

Please follow the client documentation to see how a user can use this JSON file to authenticate while using the b2handle library.