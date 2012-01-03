/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.helpers.proxy.ProxyGeneratorHelper;
import eu.emi.security.authn.x509.impl.CertificateUtils;


/**
 * Utilities to create proxy certificates.
 * 
 * @author K. Benedyczak
 */
public class ProxyGenerator
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Generate the proxy certificate object from the local certificate.
	 * 
	 * @param param proxy parameters
	 * @param privateKey key to sign the proxy
	 * @return a newly created proxy certificate, wrapped together with a private key 
	 * if it was also generated.
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateParsingException
	 */
	public static ProxyCertificate generate(ProxyCertificateOptions param,
			PrivateKey privateKey) throws InvalidKeyException,
			SignatureException, NoSuchAlgorithmException,
			CertificateParsingException
	{
		ProxyGeneratorHelper helper = new ProxyGeneratorHelper();
		return helper.generate(param, privateKey);
	}

	/**
	 * Generate the proxy certificate object from the received Certificate Signing Request.
	 *  
	 * @param param proxy parameters
	 * @param privateKey key to sign the proxy
	 * @return chain with the new proxy on the first position
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateParsingException
	 */
	public static X509Certificate[] generate(ProxyRequestOptions param,
			PrivateKey privateKey) throws InvalidKeyException,
			SignatureException, NoSuchAlgorithmException,
			CertificateParsingException
	{
		ProxyGeneratorHelper helper = new ProxyGeneratorHelper();
		return helper.generate(param, privateKey);
	}
}
