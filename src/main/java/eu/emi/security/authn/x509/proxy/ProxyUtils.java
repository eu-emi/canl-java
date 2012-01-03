/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.helpers.proxy.ExtendedProxyType;
import eu.emi.security.authn.x509.helpers.proxy.ProxyHelper;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Utility methods for checking properties of proxy certificates.
 * 
 * @author K. Benedyczak
 */
public class ProxyUtils
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Checks whether the certificate is a proxy.
	 * @param certificate the certificate to check
	 * @return true if proxy was found
	 */
	public static boolean isProxy(X509Certificate certificate)
	{
		return ProxyHelper.getProxyType(certificate) != 
				ExtendedProxyType.NOT_A_PROXY;
	}
	
	/**
	 * Checks whether the chain contains at least one proxy. Note that by definition 
	 * proxy certificate can not issue a non-proxy certificate, therefore this method 
	 * only checks the first certificate in chain. If proxy certificates are placed
	 * inside the chain and the first certificate is a not a proxy then this method will
	 * return false, but the chain is invalid.
	 *   
	 * @param certificate the chain to check
	 * @return true if proxy was found
	 */
	public static boolean isProxy(X509Certificate[] certificate)
	{
		return isProxy(certificate[0]); 
	}

	/**
	 * Extracts the first EEC from the chain.
	 * @param certificateChain chain to find EEC
	 * @return the certificate found or null if only proxy certificates are in chain
	 */
	public static X509Certificate getEndUserCertificate(X509Certificate[] certificateChain)
	{
		for (X509Certificate cert: certificateChain)
			if (!isProxy(cert))
				return cert;
		return null;
	}
	
	/**
	 * Tries to establish the DN of the user who issued 
	 * the first proxy which is found in the provided chain. 
	 * @param certificateChain chain to be checked
	 * @return object holding the user distinguished name
	 * @throws IllegalArgumentException if the argument chain contains 
	 * only proxy certificates
	 */
	public static X500Principal getOriginalUserDN(X509Certificate[] certificateChain)
		throws IllegalArgumentException
	{
		X509Certificate eec = getEndUserCertificate(certificateChain);
		if (eec == null)
			throw new IllegalArgumentException("The checked certificate chain contains only proxy certificates");
		return eec.getSubjectX500Principal();
	}	
}
