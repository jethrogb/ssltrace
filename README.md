ssltrace
========

ssltrace hooks an application's SSL libraries to record keying data of all SSL connections. By default, this data is outputted on stderr in a Wireshark-compatible format.

Supported SSL libraries:

  * OpenSSL
  * NSS [1]
  * GnuTLS

[1] Recent versions of NSS also support the SSLKEYLOGFILE environment variable, which might be easier to use.

Building
--------

Dependencies:

  * OpenSSL headers
  * NSS headers
  * NSPR (Netscape Portable Runtime) headers
  * NSS debug symbols for each NSS library you want to trace
  * GnuTLS headers
  * GnuTLS debug symbols

NSS internal structures are not defined in public headers. If you want to trace NSS, you'll need to use GDB to figure out the definition of certain internal NSS structures, and modify ``nssimpl.h`` to match. Note that you might have multiple versions of NSS on your system, and each of these could have different internal structures. For example, on Ubuntu, Firefox ships it's own NSS libraries in ``/usr/lib/firefox``.

GnuTLS internal structures are similarly not defined in public headers, but they don't change as much as NSS's.

After this, run ``make``.

Configuring output
------------------

If the environment variable SSLTRACE_LOG is set, ssltrace will try to use it as a filename to open for append and log there. If opening the file fails, ssltrace will print a message on stderr and exit.

If the file /etc/ssltrace.d/logfile exists, ssltrace will try to use the contents as a filename to open for append and log there. If opening the file fails, ssltrace will print a message on stderr and exit.

Otherwise, ssltrace will log on stderr.

Note that ssltrace won't try to open any files until it actually has to log something (which is usually when the first SSL connection gets initiated).

Testing OpenSSL
---------------

We can just use the ``openssl`` command-line utility.

Use ``s_client`` to make an SSL connection as a client:

```
LD_PRELOAD=./ssltrace.so openssl s_client -connect SOME_HOST:SOME_PORT
```

To run an OpenSSL server, you first need to generate a public/private key pair:

```
openssl req -newkey rsa:2048 -nodes -new -x509 -keyout KEY_FILE -out CERT_FILE
```

Run the ``s_server`` SSL server:

```
LD_PRELOAD=./ssltrace.so openssl s_server -accept SOME_PORT -key KEY_FILE -cert CERT_FILE
```

Testing NSS
-----------

We will use the NSS tools ``certutil``, ``tstclnt`` and ``selfserv``. These might or might not come with your distribution's NSS package [2].

First, you need to create a certificate database in some directory:

```
certutil -N -d /PATH/TO/YOUR/NSS/DB
```

Now, run ``tstclnt`` to make an SSL connection as a client:

```
LD_PRELOAD=./ssltrace.so nss/tstclnt -o -V ssl3: -h SOME_HOST -p SOME_PORT -d /PATH/TO/YOUR/NSS/DB
```

To run an NSS SSL server, you first need to generate a public/private key pair:

```
certutil -t P,P,P -x -S -d /PATH/TO/YOUR/NSS/DB -s "o=SUBJECTNAME" -n AN_IDENTIFIER
```

Run the ``selfserv`` SSL server:

```
LD_PRELOAD=./ssltrace.so selfserv -v -n AN_IDENTIFIER -p SOME_PORT -d /PATH/TO/YOUR/NSS/DB
```

[2]: On Ubuntu (and probably Debian-flavored distributions), ``certutil`` is in ``libnss3-tools``, but for ``tstclnt`` and ``selfserv`` do;
```
apt-get source nss
apt-get build-dep nss
cd nss-*
debuild -i -us -uc -b
```
Find your binaries in ``mozilla/dist/bin/``. Don't ask me why they're not included in the package while they obviously do get built by default.

Testing GnuTLS
---------------

We can just use the ``gnutls-cli`` and ``gnutls-serv`` command-line utilities.

Use ``gnutls-cli`` to make an SSL connection as a client:

```
LD_PRELOAD=./ssltrace.so gnutls-cli --insecure -p SOME_PORT SOME_HOST
```

The GnuTLS server uses the same type of keys as OpenSSL, see above on how to generate them.

Run the ``gnutls-serv`` SSL server:

```
LD_PRELOAD=./ssltrace.so gnutls-serv -p SOME_PORT --x509keyfile KEY_FILE --x509certfile CERT_FILE
```
