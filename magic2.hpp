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

/* magic: access struct members at dynamic offsets.
 * See magic3.hpp for documentation. */

		ACCESSOR_ID_LAST
		}; // enum
		#undef BEGIN_ACCESSOR
		#undef MEMBER
		#undef END_ACCESSOR
		#undef TYPEDEF

		#define BEGIN_ACCESSOR(s)
		#define MEMBER(s,type,name) #s "." #name,
		#define END_ACCESSOR(s)
		#define TYPEDEF(a,b)
		static const char* parameterNames[ACCESSOR_ID_LAST+1]={
