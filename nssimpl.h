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

// Adapted from sslimpl.h
#define ssl_HaveXmitBufLock(ss)		\
    (PZ_InMonitor((ss)->M(xmitBufLock)))
#define ssl_HaveRecvBufLock(ss)		\
    (PZ_InMonitor((ss)->M(recvBufLock)))

#define ssl_GetSpecReadLock(ss)		\
    { if (!ss->M(opt).M(noLocks)) NSSRWLock_LockRead((ss)->M(specLock)); }
#define ssl_ReleaseSpecReadLock(ss)	\
    { if (!ss->M(opt).M(noLocks)) NSSRWLock_UnlockRead((ss)->M(specLock)); }

#define ssl_Get1stHandshakeLock(ss)     \
    { if (!ss->M(opt).M(noLocks)) { \
	  PORT_Assert(PZ_InMonitor((ss)->M(firstHandshakeLock)) || \
		      !ssl_HaveRecvBufLock(ss)); \
	  PZ_EnterMonitor((ss)->M(firstHandshakeLock)); \
      } }
#define ssl_Release1stHandshakeLock(ss) \
    { if (!ss->M(opt).M(noLocks)) PZ_ExitMonitor((ss)->M(firstHandshakeLock)); }

#define ssl_GetSSL3HandshakeLock(ss)	\
    { if (!ss->M(opt).M(noLocks)) { \
	  PORT_Assert(!ssl_HaveXmitBufLock(ss)); \
	  PZ_EnterMonitor((ss)->M(ssl3HandshakeLock)); \
      } }
#define ssl_ReleaseSSL3HandshakeLock(ss) \
    { if (!ss->M(opt).M(noLocks)) PZ_ExitMonitor((ss)->M(ssl3HandshakeLock)); }

#endif // NSSIMPL_H
