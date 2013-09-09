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

#include <gnutls/gnutls.h>
#include "gnutlsimpl.h"

WRAP(int,gnutls_handshake,(gnutls_session_t session))
{
	WRAPINIT(gnutls_handshake);
	
	int ret=_gnutls_handshake(session);
	
	if (ret==GNUTLS_E_SUCCESS)
	{
		ssltrace_trace_clientrandom(((_gnutls_session_t)session)->security_parameters._.client_random._,SIZE_security_parameters_st_client_random,((_gnutls_session_t)session)->security_parameters._.master_secret._,SIZE_security_parameters_st_master_secret);
	}
	
	return ret;
}
