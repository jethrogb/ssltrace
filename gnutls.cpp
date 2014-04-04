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

#include <gnutls/gnutls.h>

namespace gnutlstypes
{
#define __accessor_exit ssltrace_die
#include "magic1.hpp"
#include "gnutlstypes.h" //enum declarations
#include "magic2.hpp"
#include "gnutlstypes.h" //parameter names array
#include "magic3.hpp"
#include "gnutlstypes.h" //struct definitions
#include "magic4.hpp"
};
using namespace gnutlstypes::__accessor;

static __attribute__((constructor)) void init_offsets()
{
	//libgnutls26:amd64=2.12.23-1ubuntu4.2
	__set_offset("security_parameters_st.master_secret",   0x16,48);
	__set_offset("security_parameters_st.client_random",   0x46,32);
	__set_offset("gnutls_session_int.security_parameters",    0,0/*TODO*/);
}

WRAP(int,gnutls_handshake,(::gnutls_session_t session))
{
	WRAPINIT(gnutls_handshake);
	
	int ret=_gnutls_handshake(session);
	
	if (ret==GNUTLS_E_SUCCESS)
	{
#define session ((gnutlstypes::__accessor::gnutls_session_t)session)
		ssltrace_trace_clientrandom(session->M(security_parameters).M(client_random),S(session->M(security_parameters).client_random),session->M(security_parameters).M(master_secret),S(session->M(security_parameters).master_secret));
#undef session
	}
	
	return ret;
}
