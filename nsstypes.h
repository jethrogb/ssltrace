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

BEGIN_ACCESSOR(ssl3CipherSpec)
	MEMBER(ssl3CipherSpec,PK11SymKey *,master_secret)
END_ACCESSOR(ssl3CipherSpec)

BEGIN_ACCESSOR(SSL3Random)
	MEMBER(SSL3Random,unsigned char[],rand)
END_ACCESSOR(SSL3Random)

BEGIN_ACCESSOR(SSL3HandshakeState)
	MEMBER(SSL3HandshakeState,SSL3Random,client_random)
END_ACCESSOR(SSL3HandshakeState)

BEGIN_ACCESSOR(ssl3State)
	MEMBER(ssl3State,ssl3CipherSpec*,cwSpec)
	MEMBER(ssl3State,SSL3HandshakeState,hs)
END_ACCESSOR(ssl3State)

BEGIN_ACCESSOR(sslOptions)
	MEMBER(sslOptions,unsigned int,noLocks)
END_ACCESSOR(sslOptions)

BEGIN_ACCESSOR(sslSocket)
	MEMBER(sslSocket,PRFileDesc*,fd)
	MEMBER(sslSocket,sslOptions,opt)
	MEMBER(sslSocket,SSLHandshakeCallback,handshakeCallback)
	MEMBER(sslSocket,void*,handshakeCallbackData)
	MEMBER(sslSocket,PZMonitor*,recvBufLock)
	MEMBER(sslSocket,PZMonitor*,xmitBufLock)
	MEMBER(sslSocket,PZMonitor*,firstHandshakeLock)
	MEMBER(sslSocket,PZMonitor*,ssl3HandshakeLock)
	MEMBER(sslSocket,NSSRWLock*,specLock)
	MEMBER(sslSocket,ssl3State,ssl3)
END_ACCESSOR(sslSocket)
