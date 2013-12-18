/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.InvalidAlgorithmParameterException;
import java.util.Collection;
import java.util.List;
import java.util.Timer;

import java.util.concurrent.atomic.AtomicReference;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.helpers.crl.PlainCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.pkipath.AbstractValidator;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;

/**
 * <p>
 * An abstract validator which provides a CRL support common for validators
 * using {@link PlainCRLStoreSpi}. Additionally it also defines a timer useful for 
 * CA or CRL updates.
 * </p><p>
 * The CRLs (Certificate Revocation Lists, if their handling is turned on) can be obtained
 * from two sources: CA certificate extension defining CRL URL and additional list
 * of URLs manually set by the class user. As an additional feature one may 
 * provide a simple paths to a local files, using wildcards. All files matching a 
 * wildcard are used.
 * </p><p>
 * Important note: this class extends {@link AbstractValidator}. Those classes are in fact 
 * unrelated, but as Java deosn't support multi inheritance we still extend it.
 * Extensions of this class must initialize {@link AbstractValidator} with its 
 * {@link AbstractValidator#init(eu.emi.security.authn.x509.helpers.trust.TrustAnchorStore, PlainCRLStoreSpi, eu.emi.security.authn.x509.ProxySupport, eu.emi.security.authn.x509.RevocationParameters)}
 * method.
 * </p><p>
 * This class is thread-safe.
 * </p>
 * 
 * @author K. Benedyczak
 * @see X509CertChainValidator
 * @see KeystoreCertChainValidator
 */
public abstract class PlainCRLValidator extends AbstractValidator
{
    protected AtomicReference<PlainCRLStoreSpi> crlStoreImplRef = new AtomicReference<PlainCRLStoreSpi>();
	protected RevocationParametersExt revocationParameters; //for CRL store recreation
	protected static final Timer timer=new Timer("caNl validator (PlainCRL) timer", true);

	/**
	 * Constructs a new validator instance. CRLs (Certificate Revocation Lists) 
	 * are taken from the trusted CAs certificate extension and downloaded, 
	 * unless CRL checking is disabled. Additional CRLs may be provided explicitly
	 * using the constructor argument. Such additional CRLs are preferred to the
	 * ones defined by the CA extensions.
	 * 
	 * @param revocationParams configuration of CRL sources
	 * @param listeners initial listeners to be notified about CRL background updates
	 */
	public PlainCRLValidator(RevocationParametersExt revocationParams,
			Collection<? extends StoreUpdateListener> listeners) 
	{
		super(listeners);
		if (revocationParams == null)
			throw new IllegalArgumentException("CRLParameters argument can not be null");
		revocationParameters = revocationParams.clone();
		crlStoreImplRef.set(createCRLStore(revocationParams.getCrlParameters(), timer));
	}

	/**
	 * This method can be overridden if a different implementation of the 
	 * {@link PlainCRLStoreSpi} (its subclass) should be used.
	 * @param crlParams source definition
	 * @param t timer to be used for scheduling updates
	 * @return initialized CRL store SPI
	 */
	protected PlainCRLStoreSpi createCRLStore(CRLParameters crlParams, Timer t)
	{
		try
		{
			PlainCRLStoreSpi ret = new PlainCRLStoreSpi(crlParams, t, observers);
			ret.start();
			return ret;
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException("BUG: PlainCRLStoreSpi " +
					"can not be initialized with CRLParameters", e);
		}
	}
	
	/**
	 * Returns a copy (so modifications won't change this validator internal state)
	 * of revocation parameters.
	 * @return revocation parameters
	 */
	public RevocationParametersExt getRevocationParameters()
	{
		return revocationParameters.clone();
	}
	
	/**
	 * Returns the interval between subsequent reloads of CRLs.
	 * This setting is used for all CRLs (those defined in CA certificates and
	 * manually configured). Implementation does not
	 * guarantees that the CRL is updated <i>exactly</i> after this interval.
	 * @return the current refresh interval in milliseconds
	 */
	public long getCRLUpdateInterval()
	{
		return crlStoreImplRef.get().getUpdateInterval();
	}

	/**
	 * Sets a new interval between subsequent of CRLs. 
	 * This setting is used for all CRLs (those defined in CA certificates and
	 * manually configured). Implementation does not
	 * guarantees that the CRL is updated <i>exactly</i> after this interval.
	 *
	 * @param updateInterval the new interval to be set in milliseconds
	 */
	public void setCRLUpdateInterval(long updateInterval)
	{
		revocationParameters.getCrlParameters().setCrlUpdateInterval(updateInterval);
		crlStoreImplRef.get().setUpdateInterval(updateInterval);
	}

	/**
	 * Returns the current list of additional CRL locations. 
	 * See class description for details.
	 * @return The current list of additional CRLs. The returned list is 
	 * a copy of the list actually used so its modifications does not influence
	 * the validator.
	 */
	public synchronized List<String> getCrls()
	{
		return crlStoreImplRef.get().getLocations();
	}

	/**
	 * Sets a new list of additional CRL locations. See class description for details.
	 * @param crls the new list.
	 */
	public synchronized void setCrls(List<String> crls)
	{
		revocationParameters.getCrlParameters().setCrls(crls);
		PlainCRLStoreSpi newCrlStoreImpl = createCRLStore(revocationParameters.getCrlParameters(), timer);
                // May still be a race condition here where the instance has been initialized
                // with the new value, but the old value is still available from the reference.
		init(null, newCrlStoreImpl, getProxySupport(), getRevocationCheckingMode());
                crlStoreImplRef.getAndSet(newCrlStoreImpl).dispose();
	}

	@Override
	public void dispose()
	{
		super.dispose();
		crlStoreImplRef.get().dispose();
	}
}





