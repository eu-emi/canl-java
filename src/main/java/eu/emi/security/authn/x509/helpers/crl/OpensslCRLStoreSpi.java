/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.crl;

import java.io.File;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.Collections;
import java.util.Timer;

import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;
import eu.emi.security.authn.x509.impl.CRLParameters;


/**
 *
 * Implementation of the CRL store which uses CRLs from a single directory 
 * in OpenSSL format. Each CRL should be stored in a file named HASH.rNUM,
 * where HASH is an 8 digit hex number, with 8 least significant digits of the MD5
 * hash of the CRL issuer subject in DER format. The NUM must be a number, starting from 0.
 * <p>
 * This class is extending the {@link PlainCRLStoreSpi} and restricts 
 * the CRLs which are loaded.
 * @author K. Benedyczak
 */
public class OpensslCRLStoreSpi extends PlainCRLStoreSpi
{
	public static final String CRL_WILDCARD = "????????.r*";
	
	public OpensslCRLStoreSpi(String path, long crlUpdateInterval, Timer t,	ObserversHandler observers)
			throws InvalidAlgorithmParameterException
	{
		super(new CRLParameters(Collections.singletonList(
				path+File.separator+CRL_WILDCARD),
				crlUpdateInterval, 0, null), t, observers);
	}
	
	/**
	 * For all URLs tries to load a CRL
	 */
	@Override
	protected void reloadCRLs(Collection<URL> locations)
	{
		for (URL location: locations)
		{
			String fileHash = OpensslTrustAnchorStore.getFileHash(location, 
					"^([0-9a-fA-F]{8})\\.r[\\d]+$");
			if (fileHash == null)
				continue;
			
			X509CRL crl;
			try
			{
				crl = loadCRL(location);
			} catch (Exception e)
			{
				notifyObservers(location.toExternalForm(), Severity.ERROR, e);
				continue;
			}
			String crlHash = OpensslTrustAnchorStore.getOpenSSLCAHash(
					crl.getIssuerX500Principal());
			if (!fileHash.equalsIgnoreCase(crlHash))
			{
				//Disabled 'cos of issue #39. Should be reenabled when support for openssl-1.0 hashes is added
				//and modified accordingly
//				notifyObservers(location.toExternalForm(), Severity.WARNING, new Exception("The CRL won't " +
//						"be used as its name has incorrect issuers's hash value. Should be " 
//						+ crlHash + " but is " + fileHash));
				continue;
			}
			notifyObservers(location.toExternalForm(), Severity.NOTIFICATION, null);
			addCRL(crl, location);
		}
	}
}
