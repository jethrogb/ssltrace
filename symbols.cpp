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

#include <dwarf.h>
#include <libdwfl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <vector>
#include <map>
#include <string>
#include <functional>
#include <algorithm>

#include "symbols.h"

using std::vector;
using std::map;
using std::string;
using std::for_each;

class DwarfReader
{
	typedef struct {
		const char* fullname;
		bool processed;
	} member_info;
	typedef map<string,member_info> members_map;
	typedef struct {
		members_map members;
		size_t processed_members;
		bool processed;
	} struct_info;
	typedef map<string,struct_info> structs_map;
	typedef std::function<bool (const vector<Dwarf_Die>& dies, bool& descend)> process_die_fn_t;

	error_fn_t m_error_fn;
	set_offset_regular_fn_t m_set_offset_regular_fn;
	set_offset_bitfield_fn_t m_set_offset_bitfield_fn;
	Dwfl* m_dwfl;
	Dwarf* m_dw;
	structs_map m_structs;
	size_t m_processed_structs;

	bool names_to_map(const char** struct_member_names)
	{
		for (auto name=*struct_member_names;name;name=*(++struct_member_names))
		{
			auto dot=strchr(name,'.');
			if (!dot) return false;
			auto& info=m_structs[string(name,dot-name)];
			info.members[string(++dot)].fullname=name;
		}
		return true;
	};
	
	bool iterate_die(Dwarf_Die* die, process_die_fn_t process_die_fn)
	{
		vector<Dwarf_Die> dies {*die};
		
		while (dies.size())
		{
			// process DIE
			bool descend;
			if (!process_die_fn(dies,descend))
				return false;
			
			Dwarf_Die child;
			if (descend&&dwarf_child(&dies.back(),&child)==0)
			{ // Have children, go down a level
				dies.push_back(child);
			}
			else
			{ // No children
				// Check if there are more siblings at this level
				while (dies.size()&&dwarf_siblingof(&dies.back(),&dies.back())!=0)
				{ // No siblings left, go up a level
					dies.pop_back();
				}
			}
		}
		return true;
	}

	void iterate_die_children(Dwarf_Die* die, process_die_fn_t process_die_fn)
	{
		Dwarf_Die child;
		if (dwarf_child(die,&child)!=0)
			return;
		
		iterate_die(&child,process_die_fn);
	}

	void iterate_all_dies(process_die_fn_t process_die_fn)
	{
		Dwarf_Off offset=0,next_unit_offset;
		enum {
			STATE_COMPILATION_UNIT,
			STATE_TYPE_UNIT,
		} process_state=STATE_COMPILATION_UNIT;

		size_t header_size;
		Dwarf_Half version;
		Dwarf_Off abbrev_offset;
		uint8_t address_size;
		uint8_t offset_size;
		uint64_t type_signature;
		Dwarf_Off type_offset;

		while(1)
		{
			if (dwarf_next_unit(
					m_dw, offset, &next_unit_offset, &header_size,
					&version, &abbrev_offset, &address_size, &offset_size,
					(process_state==STATE_TYPE_UNIT)?&type_signature:NULL,
					(process_state==STATE_TYPE_UNIT)?&type_offset:NULL
				)==0)
			{ // New unit in this state
				// Get first DIE
				Dwarf_Die die;
				offset+=header_size;
				if (((process_state==STATE_TYPE_UNIT)?dwarf_offdie_types:dwarf_offdie)(m_dw, offset, &die)==NULL)
				{
					// TODO: ERROR
					break;
				}
				
				if (!iterate_die(&die,process_die_fn))
					break;
				
				offset=next_unit_offset;
			}
			else
			{ // No more units in this state, advance state
				if (process_state==STATE_COMPILATION_UNIT)
				{
					offset=0;
					process_state=STATE_TYPE_UNIT;
				}
				else if (process_state==STATE_TYPE_UNIT)
				{
					break;
				}
			}
		}
	};
	
public:
	DwarfReader(error_fn_t error_fn, set_offset_regular_fn_t set_offset_regular_fn, set_offset_bitfield_fn_t set_offset_bitfield_fn) :
		m_error_fn(error_fn), m_set_offset_regular_fn(set_offset_regular_fn),
		m_set_offset_bitfield_fn(set_offset_bitfield_fn),
		m_dwfl(NULL), m_dw(NULL) {};
		
	~DwarfReader()
	{
		if (m_dwfl)
			dwfl_end(m_dwfl);
	};

	bool init(const char** struct_member_names)
	{
		if (!names_to_map(struct_member_names)) return false;

		static const Dwfl_Callbacks dwfl_callbacks={
			.find_elf = NULL,
			.find_debuginfo = dwfl_standard_find_debuginfo,
			.section_address = dwfl_offline_section_address,
			.debuginfo_path = NULL,
		};

		if (m_dwfl) return true;

		m_dwfl=dwfl_begin(&dwfl_callbacks);
		return m_dwfl ? true : false;
	};

	bool read(const char* file)
	{
		if (!m_dwfl) return false;
		if (m_dw) return false;
		
		dwfl_report_begin(m_dwfl);
		Dwfl_Module* mod=dwfl_report_offline(m_dwfl,"",file,-1);
		dwfl_report_end(m_dwfl,NULL,NULL);

		m_dw=NULL;
		if (mod)
		{
			Dwarf_Addr bias;
			m_dw=dwfl_module_getdwarf(mod,&bias);
		}

		return m_dw!=NULL;
	};

private:
	void parse_struct_die(Dwarf_Die* die)
	{
		auto tagt=dwarf_tag(die);
		if (tagt==DW_TAG_typedef||tagt==DW_TAG_structure_type)
		{
			auto name=dwarf_diename(die);
			if (!name) return;
			// Try to find struct with this name
			auto it=m_structs.find(string(name));

			if (it!=m_structs.end()&&!it->second.processed)
			{ // Skip if name not found or already processed
				Dwarf_Die local_die,*struct_die;
				Dwarf_Attribute attr;
				if (tagt==DW_TAG_structure_type)
				{ // struct, use DIE directly
					it->second.processed=true;
					struct_die=die;
				}
				else if (
					dwarf_attr_integrate(die,DW_AT_type,&attr) &&
					dwarf_formref_die(&attr,&local_die) &&
					dwarf_tag(&local_die)==DW_TAG_structure_type
				)
				{ // typedef, use dereferenced DIE if it points to a struct
					it->second.processed=true;
					struct_die=&local_die;
				}

				if (it->second.processed)
				{
					//printf("%s\n",it->first.c_str());
					find_members(it->second,struct_die);
					if (it->second.processed_members==it->second.members.size())
						m_processed_structs++;
					else
						it->second.processed=false;
				}
			}
		}
	};

	void parse_member_die(struct_info& sinfo, Dwarf_Die* die)
	{
		auto tagt=dwarf_tag(die);
		if (tagt==DW_TAG_member)
		{
			auto name=dwarf_diename(die);
			if (!name) return;
			// Try to find member with this name
			auto it=sinfo.members.find(string(name));

			if (it!=sinfo.members.end()&&!it->second.processed)
			{ // Skip if name not found or already processed
				//printf("  %s\n",it->first.c_str());
				if (load_member(it->second.fullname,die))
				{
					it->second.processed=true;
					sinfo.processed_members++;
				}
			}
		}
	};
	
public:
	bool find_offsets()
	{
		find_structs();
		
		if (m_processed_structs==m_structs.size())
			return true;
		
		for_each(m_structs.begin(), m_structs.end(), [&](structs_map::value_type sval)
		{
			if (sval.second.processed)
				return;
			for_each(sval.second.members.begin(), sval.second.members.end(), [&](members_map::value_type mval)
			{
				if (mval.second.processed)
					return;
				m_error_fn("Missing symbol %s",mval.second.fullname);
			});
		});
		
		return false;
	}
	
private:
	void find_structs()
	{
		iterate_all_dies([&](const vector<Dwarf_Die>& dies, bool& descend) {
			Dwarf_Die* die=const_cast<Dwarf_Die*>(&dies.back());
			parse_struct_die(die);
			descend=dies.size()<=1;
			return m_processed_structs!=m_structs.size();
		});
	}

	void find_members(struct_info& sinfo, Dwarf_Die* struct_die)
	{
		iterate_die_children(struct_die,[&](const vector<Dwarf_Die>& dies, bool& descend) {
			Dwarf_Die* die=const_cast<Dwarf_Die*>(&dies.back());
			parse_member_die(sinfo,die);
			descend=false;
			return sinfo.processed_members!=sinfo.members.size();
		});
	}
	
	bool load_member(const char* fullname, Dwarf_Die* member_die)
	{
		Dwarf_Attribute attr;
		if (!dwarf_attr_integrate(member_die,DW_AT_data_member_location,&attr))
			return false;

		Dwarf_Word offset;

		switch (dwarf_whatform(&attr))
		{
			case DW_FORM_udata:
			case DW_FORM_sdata:
			case DW_FORM_data2:
			case DW_FORM_data1:
				if (dwarf_formudata(&attr,&offset)==-1)
					return false;
				break;
			case DW_FORM_data8: //loclistptr
			case DW_FORM_data4:
				//TODO Error, can't handle loclistptr
			default:
				//TODO Error, can't handle block/exprloc
				return false;
		}
		
		int bytesize=dwarf_bytesize(member_die);
		uint16_t bitoffset=dwarf_bitoffset(member_die);
		uint16_t bitsize=dwarf_bitsize(member_die);
		if ((bitoffset==0xffff) != (bitsize==0xffff))
		{ // Only one of the bit attribute specified, bail out
			return false;
		}
		else if (bitoffset!=0xffff&&bitsize!=0xffff)
		{
			if (bytesize==-1)
				return false;
			// We currently only support DWARF 3 style bitfields on little-endian architectures
			bitoffset=bytesize*CHAR_BIT-bitsize-bitoffset;
			//printf("%s @ %td BITFIELD @ %" PRIu16 " : %" PRIu16 "\n", fullname, (ptrdiff_t)offset, bitoffset, bitsize);
			m_set_offset_bitfield_fn(fullname, offset, bitsize, bitoffset);
		}
		else
		{
			if (bytesize==-1)
			{
				Dwarf_Die type_die;
				Dwarf_Word size;
				
				if (
					dwarf_attr_integrate(member_die,DW_AT_type,&attr) &&
					dwarf_formref_die(&attr,&type_die) &&
					dwarf_aggregate_size(&type_die,&size)==0
				)
				{
					//printf("%s @ %td [%" PRIu64 "]\n", fullname, (ptrdiff_t)offset, size);
					m_set_offset_regular_fn(fullname, offset, size);
				}
				else
				{ // bytesize not specified and unable to get (size of) referenced type
					return false;
				}
			}
			else
			{
				//printf("%s @ %td [%d]\n", fullname, (ptrdiff_t)offset, bytesize);
				m_set_offset_regular_fn(fullname, offset, bytesize);
			}
		}
		return true;
	};
};

bool symbols_load_all(const char* module, const char** struct_member_names, error_fn_t error_fn, set_offset_regular_fn_t set_offset_regular, set_offset_bitfield_fn_t set_offset_bitfield)
{
	DwarfReader dwr(error_fn,set_offset_regular,set_offset_bitfield);
	
	if (!dwr.init(struct_member_names))
	{
		error_fn("Unable to intialize DWARF for %s",module);
		return false;
	}
	
	if (!dwr.read(module))
	{
		error_fn("Unable to find debug symbols for %s",module);
		return false;
	}
	
	return !dwr.find_offsets();
}
