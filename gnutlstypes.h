/**
 * ssltrace -  hook SSL libraries to record keying data of SSL connections
 * Copyright (C) 2014  Jethro G. Beekman
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

BEGIN_ACCESSOR(security_parameters_st)
	MEMBER(security_parameters_st,unsigned char[],master_secret)
	MEMBER(security_parameters_st,unsigned char[],client_random)
END_ACCESSOR(security_parameters_st)

BEGIN_ACCESSOR(gnutls_session_int)
	MEMBER(gnutls_session_int,security_parameters_st,security_parameters)
END_ACCESSOR(gnutls_session_int)

TYPEDEF(gnutls_session_int*,gnutls_session_t)
