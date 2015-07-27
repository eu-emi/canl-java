/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.crl;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.impl.CRLParameters;

/**
 * Common code for {@link LazyOpensslCRLStoreSpi} and {@link PlainCRLStoreSpi}.
 * @author K. Benedyczak
 */
public abstract class AbstractCRLStoreSPI extends CertStoreSpi
{
	protected ObserversHandler observers;
	protected CRLParameters params;
	protected final CertificateFactory factory;
	protected long updateInterval;
	
	public AbstractCRLStoreSPI(CRLParameters params, ObserversHandler observers) throws InvalidAlgorithmParameterException
	{
		super(params);
		this.observers = observers;
		this.params = params.clone();
		try
		{
			factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException e)
		{
			throw new RuntimeException("Can't find certificate fctory" +
					" for alg. X.509, JDK/BouncyCastle is misconfigured?", e);
		} catch (NoSuchProviderException e)
		{
			throw new RuntimeException("Can't load Bouncycastle CertificateFacotory" +
					" for alg. X.509, BouncyCastle is misconfigured?", e);
		}
		updateInterval = this.params.getCrlUpdateInterval();
	}

	protected void notifyObservers(String url, Severity level, Exception e)
	{
		observers.notifyObservers(url, StoreUpdateListener.CRL, level, e);
	}

	@Override
	public Collection<? extends Certificate> engineGetCertificates(
			CertSelector selector) throws CertStoreException
	{
		return Collections.emptySet();
	}

	@Override
	public Collection<? extends CRL> engineGetCRLs(CRLSelector selectorRaw)
			throws CertStoreException
	{
		if (selectorRaw instanceof X509CRLSelector)
			return getCRLs((X509CRLSelector) selectorRaw);
		else
			return getCRLWithMatcher(selectorRaw);
	}
	
	private Collection<? extends CRL> getCRLs(X509CRLSelector selector)
			throws CertStoreException
	{
		Collection<X500Principal> issuers = selector.getIssuers();
		List<X509CRL> ret = new ArrayList<X509CRL>();
		if (issuers == null)
			return ret;
		for (X500Principal issuer: issuers)
		{
			Collection<X509CRL> crls = getCRLForIssuer(issuer);
			for (X509CRL crl: crls)
				if (selector.match(crl))
					ret.add(crl);
		}
		return ret;
	}
	
	protected abstract Collection<X509CRL> getCRLForIssuer(X500Principal issuer);
	protected abstract Collection<X509CRL> getCRLWithMatcher(CRLSelector selectorRaw);
	public abstract void setUpdateInterval(long newInterval);
	public abstract void dispose();
}
