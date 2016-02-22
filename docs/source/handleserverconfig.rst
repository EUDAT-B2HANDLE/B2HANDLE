===========================
Handle Server Configuration
===========================

The methods offered by the library make calls against the Handle Server REST interface of server version 8.1.0 and later.
For security reasons, the Handle server enforces usage of SSL/TLS when contacting the REST interface. Therefore, it is required
to set up the Handle server to use proper certificates. A default installation will have a default self-signed certificate, 
which should be replaced for production scenarios. The following short guide explains how to provide a signed certificate
to the Handle server instance.

In case your clients encounter SSL warnings due to missing chain parts, you may decide to use a Java keystore to deliver the
missing parts of your certificate chain. Some hints how to do this are given further below as well. Note that the workflow is based
on a CentOS 7 installation and may be different on other operating systems. If you are not running the Handle server yourself, you need to contact the responsible
administrators and ask them to fix the issues, of course.

Replace the default certificate
===============================

The Handle server delivers a certificate taken from the *serverCertificate.pem* file in the instance directory. To replace this
with a proper certificate, do the following (based on a CentOS installation)::

1. Convert your certificate to serverCertificate.pem:

  | $ openssl x509 -in /etc/pki/tls/certs/<your .crt> -out serverCertificate.pem -outform pem

2. Convert certificate private key to pkcs8 format:

  | $ openssl pkcs8 -in /etc/pki/tls/private/<your key file> -out serverCertificatePrivateKey.pem -inform pem -nocrypt -topk8
  
3. Convert to Handle binary key format using hdl-convert-key:

  | $ ../hsj-8.1.0/bin/hdl-convert-key serverCertificatePrivateKey.pem serverCertificatePrivateKey.bin

Creating the keystore
=====================

This may be purely optional, depending on whether your clients encounter security warnings due to an incomplete security
chain and also depending on your strategy to solve the issue. The following is a description of how to provide missing
chain parts through a Java keystore.


1. Create a Java keystore based on your signed server certificate and your trust chain::

  | $ openssl pkcs12 -export -in serverCertificate.pem -inkey <private key.pem> -certfile <your CA bundle.crt> -name "handle" -out keystore.p12
  | $ keytool -importkeystore -srckeystore keystore.p12 -srcstoretype pkcs12 -destkeystore handle_keystore -deststoretype JKS

2. Set a key password::

  | $ keytool -keypasswd -keystore handle_keystore -alias handle

3. Now check with the keytool that the store contains 1 entry with a full chain. Check that the chain length is correct and all certificates in the chain are listed::

  | $ keytool -list -v -keystore handle_keystore
  

4. Finally, include a section in config.dct to load the keystore. The following properties must be included in the "hdl_http_config" sections, which may appear twice if you have a dual stack server::

  | "https_default_self_signed_cert" = "no"
  | "https_keystore_file" = "handle_keystore"
  | "https_alias" = "handle"
  | "https_keystore_password" = "..."
  | "https_key_password" = "..."

Keystore password and key password may be the same, but also differ, depending on what you entered in step 1 and 2.