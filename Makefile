all: ssltrace.so

ssltrace.so: ssltrace.c ssltrace.h openssl.c nss.c nssimpl.h gnutls.c gnutlsimpl.h
	gcc -g -shared -fPIC -std=gnu11 -Wall -I/usr/include/nspr openssl.c nss.c ssltrace.c gnutls.c -o ssltrace.so -ldl

clean:
	rm -f ssltrace.so
