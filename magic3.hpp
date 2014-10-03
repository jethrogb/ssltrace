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
 * 
 * ===========
 * == Usage ==
 * ===========
 * 
 * To use, create a file (e.g. `types.h`) with struct definitions like this:
 * 
 *   BEGIN_ACCESSOR(struct_name2)
 *     MEMBER(struct_name2,type_name3,member_name3)
 *   END_ACCESSOR(struct_name2)
 * 
 *   BEGIN_ACCESSOR(struct_name1)
 *     MEMBER(struct_name1,type_name1,member_name1)
 *     MEMBER(struct_name1,struct_name2,member_name2)
 *   END_ACCESSOR(struct_name1)
 * 
 * You don't need to define all members of the structs, only the ones that you
 * need to access in your program. The types will be defined in the `__accessor`
 * namespace.
 * 
 * In the file where you want to use these structs, you have to define a
 * function:
 * 
 *   void __accessor_exit(const char*)
 * 
 * This function will be called to indicate an error that requires immediate
 * termination. This function needs to be in the `__accessor` namespace or a
 * parent of that namespace. Then, use something like:
 * 
 *   namespace types
 *   {
 *   #include "magic1.hpp"
 *   #include "types.h" //enum declarations
 *   #include "magic2.hpp"
 *   #include "types.h" //parameter names array
 *   #include "magic3.hpp"
 *   #include "types.h" //struct definitions
 *   #include "magic4.hpp"
 *   };
 *   using namespace types::__accessor;
 * 
 * Create a intializer function that calls for each field:
 * 
 *   __set_offset("struct_name.member_name",offset,size)
 * 
 * Or, as a special case, for bitfields:
 * 
 *   __set_offset("struct_name.member_name",offset,bits,bitoffset)
 * 
 * You can hardcode this information, read it from files, obtain it from
 * debugging symbols, etc. You can call `__get_parameter_names()` to get a NULL-
 * terminated array of struct.member names (as NULL-terminated strings) that are
 * defined.
 * 
 * To use a variable `a` of type `struct_name1`, do:
 * 
 *   a.M(member_name1)
 *   a.M(member_name2).M(member_name3) // nested structs
 * 
 * Or, to get the size of a member:
 * 
 *   S(a.member_name1)
 *   S(a.M(member_name2).member_name3) // nested structs
 * 
 * These macros are designed to be compatible with a compiled version of the
 * struct definitions using:
 * 
 *   #define M(v) v
 *   #define S(v) sizeof(v)
 * 
 * Currently, if you want to obtain a reference to an integral type, you'll need
 * to obtain a pointer first and then dereference it:
 * 
 *   int& ref=*&a.M(int_member)
 * 
 * ===============
 * == Internals ==
 * ===============
 * 
 * The structure definitions in `types.h` are used three times, to:
 * 
 * 1. Define enum identifiers ("parameters") in the form
 *    ACCESSOR_ID_struct_name_member_name
 * 2. Define a char* array containing a mapping from identifiers to names in
 *    the form "struct_name.member_name"
 * 3. Define unions with name `struct_name` with a members of a special `Param`
 *    class for each member of the original struct. Each parameter has its own
 *    specialization of this class.
 * 
 * There are 4 lookup tables that contain information about the structures:
 * 
 * - offsetTable   : Holds member offset information by parameter
 * - sizeTable     : Holds member size information by parameter
 * - bitfieldTable : Holds member bitfield information by parameter
 * - initTable     : Holds lookup table intialization status by parameter
 * 
 * The Param class has two functions:
 * 
 *   T& Param<T,parameter>::resolve()
 * 
 *     Will lookup the offset for parameter `parameter` and return a reference
 *     to that offset relative to `this`.
 * 
 *   size_t Param<T,parameter>::size()
 * 
 *     Will lookup the size for parameter `parameter` and return it.
 * 
 * Both functions perform error checking to see if the parameter was initialized
 * and if the field can be accessed this way.
 * 
 * If the member is of an integral type, a special class `BitfieldAccessor` that
 * can deal with bitfields is returned.
 * 
 */

			NULL,
		}; //parameterNames[]
		#undef BEGIN_ACCESSOR
		#undef MEMBER
		#undef END_ACCESSOR
		#undef TYPEDEF

		static ptrdiff_t offsetTable[ACCESSOR_ID_LAST]={};
		static size_t sizeTable[ACCESSOR_ID_LAST]={};
		//bit size in upper 16 bits, bit offset in lower 16 bits
		static uint32_t bitfieldTable[ACCESSOR_ID_LAST]={};
		static bool initTable[ACCESSOR_ID_LAST]={};
        
		// This type should be the largest available integral type
        typedef long long unsigned int bitfield_mask_t;
		
		static inline bitfield_mask_t bit_mask(bitfield_mask_t x)
		{
			return (x>=sizeof(bitfield_mask_t)*CHAR_BIT) ? (bitfield_mask_t)-1 : (((bitfield_mask_t)1) << x)-1;
		}

		template<typename T,int parameter>
		class BitfieldAccessor
		{
		public:
			operator T() const
			{
				if (bitfieldTable[parameter])
				{
					bitfield_mask_t bitfield_mask=bit_mask(bitfieldTable[parameter]>>16);
					uint16_t bitfield_offset=bitfieldTable[parameter]&0xffff;
					T unsignedT=((*(bitfield_mask_t*)this)>>bitfield_offset)&bitfield_mask;
					if (std::is_signed<T>::value && ((bitfield_mask+1)>>1)&unsignedT) //negative
					{
						unsignedT|=~bitfield_mask; //sign-extend
					}
					return unsignedT;
				}
				else
				{
					return *(T*)this;
				}
			}

			T* operator&()
			{
				if (bitfieldTable[parameter]) __accessor_exit("Attempted to obtain a pointer to a bitfield");
				return (T*)this;
			}

			BitfieldAccessor<T,parameter>& operator=(const T v)
			{
				if (bitfieldTable[parameter])
				{
					bitfield_mask_t bitfield_mask=bit_mask(bitfieldTable[parameter]>>16);
					uint16_t bitfield_offset=bitfieldTable[parameter]&0xffff;
					*(T*)this&=~(((T)bitfield_mask)<<bitfield_offset);
					*(T*)this|=(v&bitfield_mask)<<bitfield_offset;
				}
				else
				{
					*(T*)this=v;
				}
				return *this;
			}
		};

		template<
			typename T,
			int parameter,
			typename retT = typename std::conditional<
				std::is_integral<T>::value,
				BitfieldAccessor<T, parameter>,
				T
			>::type
		>
		class Param
		{
		public:
			retT& resolve() const
			{
				if (!initTable[parameter]) __accessor_exit("Attempted to dereference unitialized offset");
				if (!std::is_integral<T>::value&&bitfieldTable[parameter]) __accessor_exit("Attempted to access bitfield that was not declared as such");
				return *(retT*)(((char*)this)+offsetTable[parameter]);
			}
            
            size_t size() const
            {
                if (!initTable[parameter]) __accessor_exit("Attempted to obtain unitialized size");
                if (bitfieldTable[parameter]) __accessor_exit("Attempted to access size of a bitfield");
                return sizeTable[parameter];
            }
		};

		static int keycmp(const void* a, const void* b)
		{
			return strcmp((const char*)a,*(const char**)b);
		}
        
        static size_t find_parameter(const char* name)
        {
            size_t num=ACCESSOR_ID_LAST;
            const char** value=(const char**)lfind(name,parameterNames,&num,sizeof(parameterNames[0]),keycmp);
            if (!value)
            {
                __accessor_exit("Attempted to set undefined offset");
            }
            return value-parameterNames;
        }

		size_t __set_offset(const char* name, ptrdiff_t offset)
		{
			size_t parameter=find_parameter(name);
			offsetTable[parameter]=offset;
			initTable[parameter]=true;
			return parameter;
		}
	}; //namespace __internal

	static const char** __get_parameter_names()
	{
		return __internal::parameterNames;
	}

	static void __set_offset(const char* name, ptrdiff_t offset, size_t size)
	{
		__internal::sizeTable[__internal::__set_offset(name,offset)]=size;
	}

	static void __set_offset(const char* name, ptrdiff_t offset, uint16_t bitfield_length, uint16_t bitfield_offset)
	{
		__internal::bitfieldTable[__internal::__set_offset(name,offset)]=(((uint32_t)bitfield_length)<<16)|(uint32_t)bitfield_offset;
	}

	#define BEGIN_ACCESSOR(s) typedef union {
	#define MEMBER(s,type,name) __internal::Param<type,__internal::ACCESSOR_ID_##s##_##name> name;
	#define END_ACCESSOR(s) } s;
	#define TYPEDEF(a,b) typedef a b;
