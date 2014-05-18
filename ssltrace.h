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

#ifndef SSLTRACE_H
#define SSLTRACE_H

#define SSLTRACE "ssltrace"
#define SSLTRACE_LOG "SSLTRACE_LOG"
#define SSLTRACE_CONF_D "/etc/ssltrace.d/"

#define WRAP(type,name,list) \
	static type (*_##name)list = NULL; \
	extern "C" type name list

#define WRAPINIT(name) \
	if (!_##name) _##name=(decltype(_##name))ssltrace_dlsym(#name); \
	if (!_##name) \
	{ \
		ssltrace_die("Unable to resolve symbol " #name); \
	}

#define WRAPINIT_FN(name,fn) \
	WRAPINIT(name); \
	fn((void*)_##name);

void *ssltrace_dlsym(const char *symbol);
void ssltrace_die(const char* message);
void ssltrace_debug(const char* fmt, ...);
void ssltrace_trace_sessionid(unsigned char* sessionid, unsigned int sessionid_length, unsigned char* masterkey, unsigned int masterkey_length);
void ssltrace_trace_clientrandom(unsigned char* clientrandom, unsigned int clientrandom_length, unsigned char* masterkey, unsigned int masterkey_length);

#endif // SSLTRACE_H
