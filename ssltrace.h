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

#ifndef SSLTRACE_H
#define SSLTRACE_H

#define _GNU_SOURCE

#include <dlfcn.h>

#define SSLTRACE "ssltrace"

#define WRAP(type,name,list) \
	static type (*_##name)list = NULL; \
	extern type name list

#define WRAPINIT(name) \
	if (!_##name) _##name=dlsym(RTLD_NEXT,#name); \
	if (!_##name) \
	{ \
		fprintf(stderr,SSLTRACE ": Unable to resolve symbol " #name "\n"); \
	}

void ssltrace_trace_sessionid(unsigned char* sessionid, unsigned int sessionid_length, unsigned char* masterkey, unsigned int masterkey_length);
void ssltrace_trace_clientrandom(unsigned char* clientrandom, unsigned int clientrandom_length, unsigned char* masterkey, unsigned int masterkey_length);

#endif // SSLTRACE_H
