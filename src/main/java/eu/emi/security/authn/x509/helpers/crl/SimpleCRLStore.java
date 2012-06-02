/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.crl;

import java.security.cert.CertStore;
import java.security.cert.CertStoreSpi;

/**
 * Provider-less implementation of the CertStore. Is a trivial wrapped
 * around {@link CertStore}, which is the real implementation.
 * 
 * @author K. Benedyczak
 */
public class SimpleCRLStore extends CertStore
{
	public SimpleCRLStore(CertStoreSpi storeSpi)
	{
		super(storeSpi, null, storeSpi.getClass().getName(), null);
	}
}
