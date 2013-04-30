/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.helpers.ObserversHandler;

/**
 * Extended PKIX parameters with additional settings related to 
 * the library features different CRL modes and proxy support.
 * @author K. Benedyczak
 */
public class ExtPKIXParameters extends ExtendedPKIXBuilderParameters
{
	protected boolean proxySupport;
	protected RevocationParameters revocationParams;
	protected ObserversHandler observers;
	private Set<TrustAnchor> unmodTrustAnchors2;

	public ExtPKIXParameters(Set<TrustAnchor> trustAnchors, Selector targetSelector, ObserversHandler observers)
			throws InvalidAlgorithmParameterException
	{
		//this calls setTrustAnchors so unmodTrustAnchors2 will be set correctly
		super(trustAnchors, targetSelector);
		this.observers = observers;
		revocationParams = new RevocationParameters(CrlCheckingMode.REQUIRE, new OCSPParametes());
		setRevocationEnabled(true);
		proxySupport = false;
	}

	public boolean isProxySupport()
	{
		return proxySupport;
	}

	public void setProxySupport(boolean proxySupport)
	{
		this.proxySupport = proxySupport;
	}

	public RevocationParameters getRevocationParams()
	{
		return revocationParams;
	}

	public ObserversHandler getObservers()
	{
		return observers;
	}

	public void setRevocationParams(RevocationParameters revocationParams)
	{
		this.revocationParams = revocationParams;
		setRevocationEnabled(revocationParams.getCrlCheckingMode() != CrlCheckingMode.IGNORE ||
				revocationParams.getOcspParameters().getCheckingMode() != OCSPCheckingMode.IGNORE);
		setUseDeltasEnabled(revocationParams.getCrlCheckingMode() != CrlCheckingMode.IGNORE);
	}

	/**
	 * We override this method as we also accept an empty list of trust anchors.
	 */
	@Override
	public void setTrustAnchors(Set<TrustAnchor> trustAnchors)
			throws InvalidAlgorithmParameterException
	{
		if (trustAnchors == null)
			throw new NullPointerException(
					"the trustAnchors parameters must"
							+ " be non-null");
		for (Iterator<TrustAnchor> i = trustAnchors.iterator(); i.hasNext();)
		{
			if (!(i.next() instanceof TrustAnchor))
				throw new ClassCastException("all elements of set must be "
						+ "of type java.security.cert.TrustAnchor");
		}
		this.unmodTrustAnchors2 = Collections.unmodifiableSet(new HashSet<TrustAnchor>(
						trustAnchors));
	}

	/**
	 * Returns an immutable <code>Set</code> of the most-trusted CAs.
	 * 
	 * @return an immutable <code>Set</code> of <code>TrustAnchor</code>s
	 *         (never <code>null</code>)
	 * 
	 * @see #setTrustAnchors
	 */
	@Override
	public Set<TrustAnchor> getTrustAnchors()
	{
		return this.unmodTrustAnchors2;
	}

	@Override
	public String toString()
	{
		String orig = super.toString();
		if (unmodTrustAnchors2 != null)
			orig = orig.replaceFirst("\\[\\n", "[\n  Trust Anchors: " + 
					unmodTrustAnchors2.toString() + "\n");
		return orig;
	}
	
	/**
	 * Makes a copy of this <code>ExtPKIXParameters</code> object. Changes to the
	 * copy will not affect the original and vice versa.
	 * 
	 * @return a copy of this <code>ExtPKIXParameters</code> object
	 */
	public ExtPKIXParameters clone()
	{
		ExtPKIXParameters params = null;
		try
		{
			params = new ExtPKIXParameters(getTrustAnchors(),
					getTargetConstraints(), getObservers());
		}
		catch (Exception e)
		{
			// cannot happen
			throw new RuntimeException(e.getMessage());
		}
		params.setParams(this);
		params.setProxySupport(proxySupport);
		params.setRevocationParams(revocationParams);
		return params;
	}


}
