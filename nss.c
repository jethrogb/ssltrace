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

#include <nss/ssl.h>
#include <nss/pk11pub.h>
#include <nss/nssrwlk.h>
#include <stdlib.h>

#include "nssimpl.h"

static int strsame(const char* a,const char* b)
{
	if (a==NULL||b==NULL)
	{
		return 0;
	}
	return 0==strcmp(a,b);
}

// Seriously, there is no built-in GetIdentityForName ???
static PRDescIdentity nss_GetIdentityForName(PRFileDesc *fd,const char* name)
{
	PRFileDesc *layer;

	for (layer = fd; layer != NULL; layer = layer->lower)
	{
		if (strsame(name,PR_GetNameForIdentity(layer->identity))) return layer->identity;
	}
	
	for (layer = fd; layer != NULL; layer = layer->higher)
	{
		if (strsame(name,PR_GetNameForIdentity(layer->identity))) return layer->identity;
	}
	
	return PR_INVALID_IO_LAYER;
}

// Adapted from sslsock.c
_sslSocket* ssl_FindSocket(PRFileDesc *fd)
{
	PRFileDesc *layer;
	_sslSocket *ss;
	static PRDescIdentity ssl_layer_id=PR_INVALID_IO_LAYER;
	if (ssl_layer_id==PR_INVALID_IO_LAYER)
	{
		ssl_layer_id=nss_GetIdentityForName(fd,"SSL");
		if (ssl_layer_id==PR_INVALID_IO_LAYER)
			return NULL;
	}

	PORT_Assert(fd != NULL);

	layer = PR_GetIdentitiesLayer(fd, ssl_layer_id);
	if (layer == NULL) {
		PORT_SetError(PR_BAD_DESCRIPTOR_ERROR);
		return NULL;
	}

	ss = (_sslSocket *)layer->secret;
	ss->fd._ = layer;
	return ss;
}

typedef struct {
		SSLHandshakeCallback cb;
		void *client_data;
} SSLHandshakeCallbackClosure;

void nss_SSLHandshakeCallback(PRFileDesc *fd,void *client_data)
{
	if (client_data)
	{
		SSLHandshakeCallbackClosure* save=(SSLHandshakeCallbackClosure*)client_data;
		save->cb(fd,save->client_data);
		// TODO: if this callback is guaranteed to be only called once, we can
		// free(client_data) now
	}
	_sslSocket*ss=ssl_FindSocket(fd);
	if (ss)
	{
		SECItem* key;
		ssl_GetSpecReadLock(ss); // This is what they do in SSL_ExportKeyingMaterial
		PK11_ExtractKeyValue(ss->ssl3._.cwSpec._->master_secret._);
		key=PK11_GetKeyData(ss->ssl3._.cwSpec._->master_secret._);
		ssltrace_trace_clientrandom(ss->ssl3._.hs._.client_random._.rand._, sizeof(ss->ssl3._.hs._.client_random._.rand._), key->data, key->len);
		ssl_ReleaseSpecReadLock(ss);
	}
}

WRAP(SECStatus,SSL_HandshakeCallback,(PRFileDesc *fd,SSLHandshakeCallback cb,void *client_data))
{
	WRAPINIT(SSL_HandshakeCallback);
	
	if (cb)
	{
		SSLHandshakeCallbackClosure* save=malloc(sizeof(SSLHandshakeCallbackClosure));
		save->cb=cb;
		save->client_data=client_data;
		client_data=save;
	}
	else
	{
		client_data=NULL;
	}
	
	SECStatus ret=_SSL_HandshakeCallback(fd,&nss_SSLHandshakeCallback,client_data);
	
	return ret;
}

WRAP(PRFileDesc*,SSL_ImportFD,(PRFileDesc *model, PRFileDesc *fd))
{
	WRAPINIT(SSL_ImportFD);
	
	PRFileDesc* ret=_SSL_ImportFD(model,fd);

	_sslSocket* ss=ssl_FindSocket(ret);
	
	SSLHandshakeCallbackClosure save={0};

	// This is what they do in SSL_HandshakeCallback
	ssl_Get1stHandshakeLock(ss);
	ssl_GetSSL3HandshakeLock(ss);
	
	if (ss->handshakeCallback._!=NULL && ss->handshakeCallback._!=&nss_SSLHandshakeCallback)
	{
		// We need to temporarily save the data, because we hold the locks
		save.cb=ss->handshakeCallback._;
		save.client_data=ss->handshakeCallbackData._;
	}
	
	ssl_ReleaseSSL3HandshakeLock(ss);
	ssl_Release1stHandshakeLock(ss);
	
	if (save.cb)
		SSL_HandshakeCallback(fd,save.cb,save.client_data);
	
	return ret;
}
