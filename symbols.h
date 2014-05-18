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

#ifndef SYMBOLS_H
#define SYMBOLS_H

#define __STDC_FORMAT_MACROS
#include <stddef.h>
#include <inttypes.h>

typedef void(*set_offset_regular_fn_t)(const char* name, ptrdiff_t offset, size_t size);
typedef void(*set_offset_bitfield_fn_t)(const char* name, ptrdiff_t offset, uint16_t bitfield_length, uint16_t bitfield_offset);
typedef void(*error_fn_t)(const char* fmt, ...);

bool symbols_load_all(const char* module, const char** struct_member_names, error_fn_t error_fn, set_offset_regular_fn_t set_offset_regular_fn, set_offset_bitfield_fn_t set_offset_bitfield_fn);

#endif // SYMBOLS_H
