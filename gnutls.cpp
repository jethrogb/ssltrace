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

#include <gnutls/gnutls.h>
#include <dlfcn.h>

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

static void load_offsets(void* fn)
{
	static bool load=false;
	if (!load)
	{
		Dl_info dli={0};
		if (dladdr(fn,&dli)==0)
		{
			ssltrace_die("Unable to get libgnutls.so filename");
		}
		else
		{
			load=symbols_load_all(dli.dli_fname,__get_parameter_names(),ssltrace_debug,__set_offset,__set_offset);
		}
	}
}

WRAP(int,gnutls_handshake,(::gnutls_session_t session))
{
	WRAPINIT_FN(gnutls_handshake,load_offsets);
	
	int ret=_gnutls_handshake(session);
	
	if (ret==GNUTLS_E_SUCCESS)
	{
#define session ((gnutlstypes::__accessor::gnutls_session_t)session)
		ssltrace_trace_clientrandom(session->M(security_parameters).M(client_random),S(session->M(security_parameters).client_random),session->M(security_parameters).M(master_secret),S(session->M(security_parameters).master_secret));
#undef session
	}
	
	return ret;
}
