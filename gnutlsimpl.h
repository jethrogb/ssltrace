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

#ifndef GNUTLSIMPL_H
#define GNUTLSIMPL_H

// in gdb: p &(( struct_name*)0)-> member_name
#define OFFSET_security_parameters_st_master_secret 0x16
#define OFFSET_security_parameters_st_client_random 0x46
#define OFFSET_gnutls_session_int_security_parameters 0

// in gdb: p sizeof((( struct_name*)0)-> member_name)
#define SIZE_security_parameters_st_master_secret 48
#define SIZE_security_parameters_st_client_random 32

// Adapted from gnutls_int.h
typedef struct {
	union {
		struct {
			unsigned char __[OFFSET_security_parameters_st_master_secret];
			unsigned char _[SIZE_security_parameters_st_master_secret];
		} master_secret;
		struct
		{
			unsigned char __[OFFSET_security_parameters_st_client_random];
			unsigned char _[SIZE_security_parameters_st_client_random];
		} client_random;
	};
} _security_parameters_st;

struct _gnutls_session_int {
	union {
		struct {
			unsigned char __[OFFSET_gnutls_session_int_security_parameters];
			_security_parameters_st _;
		} security_parameters;
	};
};

typedef struct _gnutls_session_int *_gnutls_session_t;

#endif // GNUTLSIMPL_H
