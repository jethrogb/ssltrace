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

#ifndef NSSIMPL_H
#define NSSIMPL_H

// in gdb: p &(( struct_name*)0)-> member_name
#define OFFSET_ssl3CipherSpec_master_secret 0x78
#define OFFSET_SSL3Random_rand 0
#define OFFSET_SSL3HandshakeState_client_random 0x20
#define OFFSET_ssl3State_cwSpec 0x10
#define OFFSET_ssl3State_hs 0x60
#define OFFSET_sslOptions_noLocks 0x18
#define OFFSET_sslSocket_fd 0
#define OFFSET_sslSocket_opt 0x10
#define OFFSET_sslSocket_handshakeCallback 0x300
#define OFFSET_sslSocket_handshakeCallbackData 0x308
#define OFFSET_sslSocket_recvBufLock 0x348
#define OFFSET_sslSocket_xmitBufLock 0x350
#define OFFSET_sslSocket_firstHandshakeLock 0x358
#define OFFSET_sslSocket_ssl3HandshakeLock 0x360
#define OFFSET_sslSocket_specLock 0x368
//#define OFFSET_sslSocket_ssl3 0x598 // libnss3:amd64=3.14.3-0ubuntu0.12.10.1
#define OFFSET_sslSocket_ssl3 0x5c0 // firefox:amd64=23.0+build2-0ubuntu0.12.10.1

// in gdb: p sizeof((( struct_name*)0)-> member_name)
#define SIZE_SSL3Random_rand 32

// in gdb: ptype struct_name
// ...  and then some hand calculations
#define BITOFF_sslOptions_noLocks 16



// Adapted from sslimpl.h
#define ssl_HaveXmitBufLock(ss)		\
    (PZ_InMonitor((ss)->xmitBufLock._))
#define ssl_HaveRecvBufLock(ss)		\
    (PZ_InMonitor((ss)->recvBufLock._))

#define ssl_GetSpecReadLock(ss)		\
    { if (!ss->opt._.noLocks._) NSSRWLock_LockRead((ss)->specLock._); }
#define ssl_ReleaseSpecReadLock(ss)	\
    { if (!ss->opt._.noLocks._) NSSRWLock_UnlockRead((ss)->specLock._); }

#define ssl_Get1stHandshakeLock(ss)     \
    { if (!ss->opt._.noLocks._) { \
	  PORT_Assert(PZ_InMonitor((ss)->firstHandshakeLock._) || \
		      !ssl_HaveRecvBufLock(ss)); \
	  PZ_EnterMonitor((ss)->firstHandshakeLock._); \
      } }
#define ssl_Release1stHandshakeLock(ss) \
    { if (!ss->opt._.noLocks._) PZ_ExitMonitor((ss)->firstHandshakeLock._); }

#define ssl_GetSSL3HandshakeLock(ss)	\
    { if (!ss->opt._.noLocks._) { \
	  PORT_Assert(!ssl_HaveXmitBufLock(ss)); \
	  PZ_EnterMonitor((ss)->ssl3HandshakeLock._); \
      } }
#define ssl_ReleaseSSL3HandshakeLock(ss) \
    { if (!ss->opt._.noLocks._) PZ_ExitMonitor((ss)->ssl3HandshakeLock._); }



typedef struct {
	union {
		struct {
			char __[OFFSET_ssl3CipherSpec_master_secret];
			PK11SymKey *_;
		} master_secret;
	};
} _ssl3CipherSpec;

typedef struct {
	union {
		struct {
			char __[OFFSET_SSL3Random_rand];
			unsigned char _[SIZE_SSL3Random_rand];
		} rand;
	};
} _SSL3Random;

typedef struct {
	union {
		struct {
			char __[OFFSET_SSL3HandshakeState_client_random];
			_SSL3Random _;
		} client_random;
	};
} _SSL3HandshakeState;

typedef struct {
	union {
		struct {
			char __[OFFSET_ssl3State_cwSpec];
			_ssl3CipherSpec *_;
		} cwSpec;
		struct {
			char __[OFFSET_ssl3State_hs];
			_SSL3HandshakeState _;
		} hs;
	};
} _ssl3State;

typedef struct {
	union {
		struct {
			char __[OFFSET_sslOptions_noLocks];
			unsigned int __b : BITOFF_sslOptions_noLocks;
			unsigned int _ : 1;
		} noLocks;
	};
} _sslOptions;

typedef struct {
	union {
		struct {
			char __[OFFSET_sslSocket_fd];
			PRFileDesc* _;
		} fd;
		struct {
			char __[OFFSET_sslSocket_opt];
			_sslOptions _;
		} opt;
		struct {
			char __[OFFSET_sslSocket_handshakeCallback];
			SSLHandshakeCallback _;
		} handshakeCallback;
		struct {
			char __[OFFSET_sslSocket_handshakeCallbackData];
			void* _;
		} handshakeCallbackData;
		struct {
			char __[OFFSET_sslSocket_recvBufLock];
			PZMonitor* _;
		} recvBufLock;
		struct {
			char __[OFFSET_sslSocket_xmitBufLock];
			PZMonitor* _;
		} xmitBufLock;
		struct {
			char __[OFFSET_sslSocket_firstHandshakeLock];
			PZMonitor* _;
		} firstHandshakeLock;
		struct {
			char __[OFFSET_sslSocket_ssl3HandshakeLock];
			PZMonitor* _;
		} ssl3HandshakeLock;
		struct {
			char __[OFFSET_sslSocket_specLock];
			NSSRWLock* _;
		} specLock;
		struct {
			char __[OFFSET_sslSocket_ssl3];
			_ssl3State _;
		} ssl3;
	};
} _sslSocket;

#endif // NSSIMPL_H
