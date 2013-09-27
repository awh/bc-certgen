Example demonstrating pure Java generation of authority, server and client certificates using the BouncyCastle JSSE crypto provider.

Outputs:

* Authority, server and client certificates + keypairs in DER format for use with OpenSSL based servers (e.g. NGINX)
* Server certificate + keypair in Java keystore format for use with JSSE based servers (e.g. Jetty)
* Client certificate + keypair in PKCS12 format understood by web browsers
