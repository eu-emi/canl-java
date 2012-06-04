/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 *
 * Derived from the code copyrighted and licensed as follows:
 * 
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.emi.security.authn.x509.impl;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

import eu.emi.security.authn.x509.helpers.ssl.HostnameToCertificateChecker;

/**
 * Abstract implementation of the JSSE {@link HandshakeCompletedListener} 
 * which can be registered on a {@link SSLSocket} to verify if a peer's 
 * host name matches a DN of its certificate. It is useful on client side
 * when connecting to a server.
 * <p>
 * By default the implementation checks the certificate's Subject Alternative Name 
 * and Common Name, following the server identity part of RFC 2818. Additionally the
 * 'service/hostname' syntax is supported (the service prefix is simply ignored).
 * <p> 
 * If there is a name mismatch the nameMismatch() method is called. 
 * User of this class must extend it and provide the application specific reaction 
 * in this method.
 * <p>
 * Note that this class should be used only on SSL connections which are
 * authenticated with X.509 certificates.
 *
 * @deprecated Use {@link SocketFactoryCreator#connectWithHostnameChecking(SSLSocket, HostnameMismatchCallback)} 
 * instead. This class is not perfect as the {@link HandshakeCompletedListener} is invoked (at least in reference JDK)
 * in a separate thread, what can easily lead to a situation when the connection is opened and made available,
 * before this implementation finishes checking. 
 * @author Joni Hahkala
 * @author K. Benedyczak
 * 
 */
@Deprecated
public abstract class AbstractHostnameToCertificateChecker implements HandshakeCompletedListener
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	public void handshakeCompleted(HandshakeCompletedEvent hce)
	{
		X509Certificate cert;
		try
		{
			Certificate[] serverChain = hce.getPeerCertificates();
			if (serverChain == null || serverChain.length == 0)
			{
				processingError(hce, new Exception("JDK BUG? Got null or empty peer certificate array"));
				return;
			}
			if (!(serverChain[0] instanceof X509Certificate))
			{
				processingError(hce, new ClassCastException("Peer certificate should be " +
						"an X.509 certificate, but is " + serverChain[0].getClass().getName()));
				return;
			}
			cert = (X509Certificate) serverChain[0];
		} catch (SSLPeerUnverifiedException e)
		{
			processingError(hce, new Exception("Peer is unverified " +
					"when handshake is completed - is it really an X.509-authenticated connection?", e));
			return;
		}
		String hostname = hce.getSocket().getInetAddress().getHostName();
		
		try
		{
			HostnameToCertificateChecker checker = new HostnameToCertificateChecker();
			if (!checker.checkMatching(hostname, cert))
				nameMismatch(hce, cert, hostname);
		} catch (Exception e)
		{
			processingError(hce, e);
			return;
		}
	}

	/**
	 * This method is called whenever peer's host name is not matching the peer's 
	 * certificate DN. Note that throwing exceptions from this method doesn't make any sense. 
	 * @param hce the original event object
	 * @param peerCertificate peer's certificate (for convenience) 
	 * @param hostName peer's host name (for convenience)
	 */
	protected abstract void nameMismatch(HandshakeCompletedEvent hce, X509Certificate peerCertificate,
			String hostName) throws SSLException;
	
	/**
	 * This method is called whenever there is an error when processing the peer's certificate
	 * and hostname. Generally it should never happen, and the implementation should simply 
	 * close the socket and report the error. The default implementation simply throws an 
	 * {@link IllegalStateException}. 
	 * @param hce the original event object
	 * @param e error
	 */
	protected void processingError(HandshakeCompletedEvent hce, Exception e)
	{
		throw new IllegalStateException("Error occured when verifying if the SSL peer's " +
				"hostname matches its certificate", e);
	}
}









