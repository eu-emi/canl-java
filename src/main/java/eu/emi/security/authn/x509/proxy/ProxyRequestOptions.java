/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Holds parameters which are used to issue a proxy certificate 
 * using a provided Certificate Signing Request and a local certificate chain.
 * 
 * Used for example when creating a proxy certificate on the client 
 * side from a certificate request coming from a service.
 *
 * @author K. Benedyczak
 */
public class ProxyRequestOptions extends BaseProxyCertificateOptions
{
	private PKCS10CertificationRequest proxyRequest;
	
	/**
	 * Create a new proxy certificate based on certification request and
	 * a certificate chain. Used for example when creating a proxy
	 * certificate on the client side from certificate request coming from a
	 * service.
	 */
	public ProxyRequestOptions(X509Certificate[] parentCertChain,
			PKCS10CertificationRequest certReq)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException
	{
		super(parentCertChain);
		this.proxyRequest = certReq;
	}

	/**
	 * @return the Certification Request that was used to create this object
	 */
	public PKCS10CertificationRequest getProxyRequest()
	{
		return proxyRequest;
	}
}
