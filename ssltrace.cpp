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

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

static FILE* ssltrace_log_handle()
{
	static FILE* fp=NULL;
	if (fp!=NULL) return fp;
	int configured=0;
	if (getenv(SSLTRACE_LOG)&&strlen(getenv(SSLTRACE_LOG)))
	{
		configured=1;
		fp=fopen(getenv(SSLTRACE_LOG),"a");
	}
	else
	{
		if ( (fp=fopen(SSLTRACE_CONF_D "logfile","r")) )
		{
			configured=1;
			char filename[2048];
			filename[0]=0;
			fgets(filename,2048,fp);
			fclose(fp);
			for (char *p=filename;*p;p++)
			{
				if (*p=='\n')
				{
					*p=0;
					break;
				}
			}
			fp=fopen(filename,"a");
		}
	}
	if (fp==NULL)
	{
		fp=stderr;
		if (configured) ssltrace_die(strerror(errno));
	}
	return fp;
}

typedef struct {
		const char *symbol;
		void *self;
		void **ret;
} DLIteratePhdrCallbackClosure;

static int ssltrace_dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *cbdata)
{
	DLIteratePhdrCallbackClosure* data=(DLIteratePhdrCallbackClosure*)cbdata;

	// Ignore main program and ssltrace lib
	if (!info->dlpi_addr || !info->dlpi_name || !info->dlpi_name[0] || data->self==(void*)info->dlpi_addr)
		return 0;
	
	// Not sure how to input info->dlpi_addr into dlsym, so just use dlopen
	void *dlh=dlopen(info->dlpi_name,RTLD_LAZY);
	*(data->ret)=dlsym(dlh,data->symbol);
	if (*(data->ret))
	{
		//stop if we found something
		return 1;
	}
	else
	{
		dlclose(dlh);
		return 0;
	}
}

void *ssltrace_dlsym(const char *symbol)
{
	void *ret=dlsym(RTLD_NEXT,symbol);
	if (!ret) // dlsym failed, try iterating all loaded libraries manually
	{
		static Dl_info dli={0};
		DLIteratePhdrCallbackClosure data={symbol,0,&ret};
		if (!dli.dli_fbase&&!dladdr((void*)&ssltrace_dlsym,&dli))
		{
			ssltrace_die("Unable to find information about " SSLTRACE " module.");
		}
		data.self=dli.dli_fbase;
		dl_iterate_phdr(&ssltrace_dl_iterate_phdr_callback, &data);
	}
	return ret;
}

void ssltrace_debug(const char* fmt, ...)
{
	va_list ap;

	fputs(SSLTRACE ": ",ssltrace_log_handle());
	va_start(ap, fmt);vfprintf(stderr, fmt, ap);va_end(ap);
	fputc('\n',ssltrace_log_handle());
	fflush(ssltrace_log_handle());
}

void ssltrace_die(const char* message)
{
	fprintf(ssltrace_log_handle(),SSLTRACE ": %s\n",message);
	fflush(ssltrace_log_handle());
	exit(1);
}

static void ssltrace_eprintf_snx(const char* s, unsigned char* x, unsigned int n)
{
	unsigned int i;
	
	fputs(s,ssltrace_log_handle());
	for (i=0;i<n;i++)
	{
		fprintf(ssltrace_log_handle(),"%02X",(unsigned int)x[i]);
	}
}

void ssltrace_trace_sessionid(unsigned char* sessionid, unsigned int sessionid_length, unsigned char* masterkey, unsigned int masterkey_length)
{
	ssltrace_eprintf_snx("RSA Session-ID:",sessionid,sessionid_length);
	ssltrace_eprintf_snx(" Master-Key:",masterkey,masterkey_length);
	putc('\n',ssltrace_log_handle());
	fflush(ssltrace_log_handle());
}

void ssltrace_trace_clientrandom(unsigned char* clientrandom, unsigned int clientrandom_length, unsigned char* masterkey, unsigned int masterkey_length)
{
	ssltrace_eprintf_snx("CLIENT_RANDOM ",clientrandom,clientrandom_length);
	ssltrace_eprintf_snx(" ",masterkey,masterkey_length);
	putc('\n',ssltrace_log_handle());
	fflush(ssltrace_log_handle());
}
