/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.CertPathParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.helpers.ObserversHandler;

/**
 * Extended PKIX parameters with additional settings related to 
 * the library features: different CRL modes and proxy support.
 * @author K. Benedyczak
 */
public class ExtPKIXParameters2 implements CertPathParameters
{
	public static class Builder
	{
		private PKIXExtendedParameters.Builder baseBuilder;
		private boolean proxySupport;
		private RevocationParameters revocationParams;
		private ObserversHandler observers;
		private PKIXParameters baseOfBase;
		
		public Builder(PKIXExtendedParameters.Builder baseBuilder, 
				PKIXParameters baseOfBase, Set<TrustAnchor> trustAnchors,
				ObserversHandler observers)
		{
			this.baseOfBase = baseOfBase;
			this.observers = observers;
			this.revocationParams = new RevocationParameters(CrlCheckingMode.REQUIRE, new OCSPParametes());
			this.baseBuilder = baseBuilder;
			setTrustAnchors(trustAnchors);
		}
		
		public Builder setProxySupport(boolean proxySupport)
		{
			this.proxySupport = proxySupport;
			return this;
		}
		
		
		public Builder setRevocationParams(RevocationParameters revocationParams)
		{
			this.revocationParams = revocationParams;
			baseBuilder.setRevocationEnabled(
					revocationParams.getCrlCheckingMode() != CrlCheckingMode.IGNORE ||
					revocationParams.getOcspParameters().getCheckingMode() != OCSPCheckingMode.IGNORE);
			baseBuilder.setUseDeltasEnabled(
					revocationParams.getCrlCheckingMode() != CrlCheckingMode.IGNORE);
			return this;
		}

		public Builder setTrustAnchors(Set<TrustAnchor> trustAnchors)
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
			baseBuilder.setTrustAnchors(trustAnchors);
			return this;
		}
		
		public ExtPKIXParameters2 build()
		{
			PKIXExtendedParameters pkixExtParameters = baseBuilder.build();
			PKIXExtendedBuilderParameters pkixExtBuildParams = new PKIXExtendedBuilderParameters.Builder(
					pkixExtParameters).build();
			return new ExtPKIXParameters2(pkixExtParameters, pkixExtBuildParams, this);
		}
	}
	
	protected final PKIXExtendedParameters base;
	protected final PKIXExtendedBuilderParameters baseExt;
	protected final PKIXParameters baseOfBase;
	protected final boolean proxySupport;
	protected final RevocationParameters revocationParams;
	protected final ObserversHandler observers;

	public ExtPKIXParameters2(PKIXExtendedParameters base, PKIXExtendedBuilderParameters baseExt, Builder builder)
	{
		this.base = base;
		this.baseExt = baseExt;
		this.baseOfBase = builder.baseOfBase;
		this.revocationParams = builder.revocationParams;
		this.observers = builder.observers;
		this.proxySupport = builder.proxySupport;
	}

	public PKIXExtendedParameters getBaseParameters()
	{
		return base;
	}

	public PKIXExtendedBuilderParameters getBaseBuildParameters()
	{
		return baseExt;
	}

	public boolean isProxySupport()
	{
		return proxySupport;
	}


	public RevocationParameters getRevocationParams()
	{
		return revocationParams;
	}

	public PKIXParameters getBaseOfBase()
	{
		return baseOfBase;
	}

	public ObserversHandler getObservers()
	{
		return observers;
	}

	@Override
	public String toString()
	{
		String orig = super.toString();
		if (base.getTrustAnchors() != null)
			orig = orig.replaceFirst("[\n", "[\n  Trust Anchors: " + 
					base.getTrustAnchors().toString() + "\n");
		return orig;
	}
	
	@Override
	public ExtPKIXParameters2 clone()
	{
		return this;
	}
}
