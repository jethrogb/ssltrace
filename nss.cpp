/**
 * ssltrace -  hook SSL libraries to record keying data of SSL connections
 * Copyright (C) 2013,2014  Jethro G. Beekman
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
#include "symbols.h"

#include <nss/ssl.h>
#include <nss/pk11pub.h>
#include <nss/nssrwlk.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

namespace nsstypes
{
#define __accessor_exit ssltrace_die
#include "magic1.hpp"
#include "nsstypes.h" //enum declarations
#include "magic2.hpp"
#include "nsstypes.h" //parameter names array
#include "magic3.hpp"
#include "nsstypes.h" //struct definitions
#include "magic4.hpp"
};
using namespace nsstypes::__accessor;

#include "nssimpl.h"

static void load_offsets(void* fn)
{
	static bool load=false;
	if (!load)
	{
		Dl_info dli={0};
		if (dladdr(fn,&dli)==0)
		{
			ssltrace_die("Unable to get libssl3.so filename");
		}
		else
		{
			load=symbols_load_all(dli.dli_fname,__get_parameter_names(),ssltrace_debug,__set_offset,__set_offset);
		}
	}
}

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
sslSocket* ssl_FindSocket(PRFileDesc *fd)
{
	PRFileDesc *layer;
	sslSocket *ss;
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

	ss = (sslSocket *)layer->secret;
	ss->M(fd) = layer;
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
	sslSocket*ss=ssl_FindSocket(fd);
	if (ss)
	{
		SECItem* key;
		ssl_GetSpecReadLock(ss); // This is what they do in SSL_ExportKeyingMaterial
		PK11_ExtractKeyValue(ss->M(ssl3).M(cwSpec)->M(master_secret));
		key=PK11_GetKeyData(ss->M(ssl3).M(cwSpec)->M(master_secret));
		ssltrace_trace_clientrandom(ss->M(ssl3).M(hs).M(client_random).M(rand), S(ss->M(ssl3).M(hs).M(client_random).rand), key->data, key->len);
		ssl_ReleaseSpecReadLock(ss);
	}
}

WRAP(SECStatus,SSL_HandshakeCallback,(PRFileDesc *fd,SSLHandshakeCallback cb,void *client_data))
{
	WRAPINIT_FN(SSL_HandshakeCallback,load_offsets);
	
	if (cb)
	{
		SSLHandshakeCallbackClosure* save=(SSLHandshakeCallbackClosure*)malloc(sizeof(SSLHandshakeCallbackClosure));
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
	WRAPINIT_FN(SSL_ImportFD,load_offsets);
	
	PRFileDesc* ret=_SSL_ImportFD(model,fd);

	sslSocket* ss=ssl_FindSocket(ret);
	
	SSLHandshakeCallbackClosure save={0};

	// This is what they do in SSL_HandshakeCallback
	ssl_Get1stHandshakeLock(ss);
	ssl_GetSSL3HandshakeLock(ss);
	
	if (ss->M(handshakeCallback)!=NULL && ss->M(handshakeCallback)!=&nss_SSLHandshakeCallback)
	{
		// We need to temporarily save the data, because we hold the locks
		save.cb=ss->M(handshakeCallback);
		save.client_data=ss->M(handshakeCallbackData);
	}
	
	ssl_ReleaseSSL3HandshakeLock(ss);
	ssl_Release1stHandshakeLock(ss);
	
	if (save.cb)
		SSL_HandshakeCallback(fd,save.cb,save.client_data);
	
	return ret;
}
