/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.cert.X509Certificate;

import java.security.cert.CertificateException;

/**
 * Implementation should react to the event when remote SSL peer's certificate is not matching its hostname. 
 * @author K. Benedyczak
 */
public interface HostnameMismatchCallback2
{
	/**
	 * This method is called whenever peer's host name is not matching the peer's 
	 * certificate DN. The method can log the problem/display a popup with a question what to do or simply 
	 * can throw an exception indicating that the socket should be closed 
	 * @param peerCertificate peer's certificate (for convenience) 
	 * @param hostName peer's host name (for convenience)
	 * @throws CertificateException if the error is considered fatal and the socket should be closed
	 */
	void nameMismatch(X509Certificate peerCertificate, String hostName) throws CertificateException;

}
