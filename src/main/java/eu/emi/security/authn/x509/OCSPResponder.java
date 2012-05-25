/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.net.URL;
import java.security.cert.X509Certificate;

/**
 * Configuration of a local responder. Should contain its address and a (trusted) certificate, which
 * the responder is using for signing the responses. 
 * @author K. Benedyczak
 */
public class OCSPResponder
{
	private URL address;
	private X509Certificate certificate;
	
	/**
	 * Creates a new instance
	 * @param address responder URL
	 * @param certificate responder's certificate
	 */
	public OCSPResponder(URL address, X509Certificate certificate)
	{
		this.address = address;
		this.certificate = certificate;
	}
	
	public URL getAddress()
	{
		return address;
	}

	public void setAddress(URL address)
	{
		this.address = address;
	}

	public X509Certificate getCertificate()
	{
		return certificate;
	}

	public void setCertificate(X509Certificate certificate)
	{
		this.certificate = certificate;
	}
}