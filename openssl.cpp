/**
 * ssltrace -  hook SSL libraries to record keying data of SSL connections
 * Copyright (C) 2013  Jethro G. Beekman
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "ssltrace.h"

#include <openssl/ssl.h>

#define min(a,b) (((a)<(b))?(a):(b))
static void openssl_dump_session(SSL* ssl)
{
	if (ssl->s3)
	{
		ssltrace_trace_clientrandom(ssl->s3->client_random,SSL3_RANDOM_SIZE,ssl->session->master_key,min(ssl->session->master_key_length,SSL_MAX_MASTER_KEY_LENGTH));
	}
	else
	{
		ssltrace_trace_sessionid(ssl->session->session_id,min(ssl->session->session_id_length,SSL_MAX_MASTER_KEY_LENGTH),ssl->session->master_key,min(ssl->session->master_key_length,SSL_MAX_MASTER_KEY_LENGTH));
	}
}

WRAP(int,SSL_connect,(SSL *ssl))
{
	WRAPINIT(SSL_connect);
	
	if (!ssl->handshake_func) SSL_set_connect_state(ssl);

	ssl->handshake_func=&SSL_connect;
	
	int ret=_SSL_connect(ssl);
	
	if (ret==1)
		openssl_dump_session(ssl);
	
	return ret;
}

WRAP(int,SSL_accept,(SSL *ssl))
{
	WRAPINIT(SSL_accept);
	
	if (!ssl->handshake_func) SSL_set_accept_state(ssl);

	ssl->handshake_func=&SSL_accept;
	
	int ret=_SSL_accept(ssl);
	
	if (ret==1)
		openssl_dump_session(ssl);
	
	return ret;
}

WRAP(void,SSL_set_connect_state,(SSL *s))
{
	WRAPINIT(SSL_set_connect_state);
	
	_SSL_set_connect_state(s);

	s->handshake_func=&SSL_connect;
}

WRAP(void,SSL_set_accept_state,(SSL *s))
{
	WRAPINIT(SSL_set_accept_state);
	
	_SSL_set_accept_state(s);

	s->handshake_func=&SSL_accept;
}

WRAP(int,SSL_set_ssl_method,(SSL *s, const SSL_METHOD *meth))
{
	int conn=-1;
	
	WRAPINIT(SSL_set_ssl_method);

	conn=(s->handshake_func == s->method->ssl_connect);
	
	int ret=_SSL_set_ssl_method(s,meth);
	
	s->handshake_func=conn?&SSL_connect:&SSL_accept;
	
	return ret;
}
