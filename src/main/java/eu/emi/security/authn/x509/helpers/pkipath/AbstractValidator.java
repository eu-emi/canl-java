/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.crl.PlainCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.crl.SimpleCRLStore;
import eu.emi.security.authn.x509.helpers.trust.TrustAnchorStore;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Base implementation of {@link X509CertChainValidator}.
 * It is configured with {@link CertStore} providing CRLs and {@link TrustAnchorStore}
 * providing trusted CAs. The implementation validates certificates using 
 * the {@link BCCertPathValidator}.
 * <p>
 * This class is thread safe and its extensions should also guarantee this.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractValidator implements X509CertChainValidatorExt
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	protected Set<ValidationErrorListener> listeners;
	protected final ObserversHandler observers;
	private TrustAnchorStore caStore;
	private PlainCRLStoreSpi crlStore;
	protected BCCertPathValidator validator;
	private ProxySupport proxySupport;
	private RevocationParameters revocationMode;
	protected boolean disposed;
	
	/**
	 * Default constructor is available, the subclass must initialize the parent 
	 * with the init() method. Note that it is strongly suggested to call the init() method
	 * from the child class constructor. 
	 * <p>
	 * This is not a cleanest design possible but it is required as arguments to the init()
	 * method require some code to be created in subclasses. Therefore we have a trade off:
	 * a bit unclean design inside the library and a clean external API without factory methods.
	 */
	public AbstractValidator(Collection<? extends StoreUpdateListener> initialListeners)
	{
		observers = new ObserversHandler(initialListeners);
		listeners = new LinkedHashSet<ValidationErrorListener>();
	}

	/**
	 * Use this method to initialize the parent from the extension class, if not using
	 * the non-default constructor.
	 */
	protected synchronized void init(TrustAnchorStore caStore, PlainCRLStoreSpi crlStore, 
			ProxySupport proxySupport, RevocationParameters revocationCheckingMode)
	{
		disposed = false;
		if (caStore != null)
			this.caStore = caStore;
		if (crlStore != null)
			this.crlStore = crlStore;
		this.validator = new BCCertPathValidator();
		this.proxySupport = proxySupport;
		this.revocationMode = revocationCheckingMode;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ValidationResult validate(CertPath certPath)
	{
		List<? extends Certificate> certs = certPath.getCertificates();
		X509Certificate[] certsA = new X509Certificate[certs.size()];
		for (int i=0; i<certsA.length; i++)
		{
			Certificate c = certs.get(i);
			if (!(c instanceof X509Certificate))
				throw new IllegalArgumentException("Can validate only " +
						"X509Certificate chains. Found instance of: " + 
						c.getClass().getName());
			certsA[i] = (X509Certificate) c;
		}
		return validate(certsA);	
	}

	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized ValidationResult validate(X509Certificate[] certChain)
	{
		if (disposed)
			throw new IllegalStateException("The validator instance was disposed");
		ValidationResult result;
		try
		{
			result = validator.validate(certChain, proxySupport == ProxySupport.ALLOW, caStore.getTrustAnchors(),
					new SimpleCRLStore(crlStore), revocationMode.getCrlCheckingMode());
		} catch (CertificateException e)
		{
			ValidationError error = new ValidationError(certChain, -1, ValidationErrorCode.inputError, 
					e.toString());
			result = new ValidationResult(false, Collections.singletonList(error));
		}

		if (!result.isValid())
		{
			List<ValidationError> errors = result.getErrors();
			processErrorList(errors);
			if (result.getErrors().size() == 0 && 
					result.getUnresolvedCriticalExtensions().size() == 0)
				return new ValidationResult(true);
		}
		
		return result;
	}
	
	protected void processErrorList(List<ValidationError> errors)
	{
		for (int i=0; i<errors.size(); i++)
		{
			boolean res = notifyListeners(errors.get(i));
			if (res)
			{
				errors.remove(i);
				i--;
			}
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized X509Certificate[] getTrustedIssuers()
	{
		return caStore.getTrustedCertificates();
	}
	

	/**
	 * Notifies all registered listeners.
	 * @param error
	 * @return true if the error should be ignored false otherwise.
	 */
	protected boolean notifyListeners(ValidationError error)
	{
		synchronized (listeners)
		{
			for (ValidationErrorListener listener: listeners)
				if (listener.onValidationError(error))
					return true;
		}
		return false;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addValidationListener(ValidationErrorListener listener)
	{
		synchronized (listeners)
		{
			listeners.add(listener);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeValidationListener(ValidationErrorListener listener)
	{
		synchronized (listeners)
		{
			listeners.remove(listener);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized ProxySupport getProxySupport()
	{
		return proxySupport;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized RevocationParameters getRevocationCheckingMode()
	{
		return revocationMode;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized void dispose()
	{
		disposed = true;
		observers.removeAllObservers();
		crlStore.dispose();
		caStore.dispose();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addUpdateListener(StoreUpdateListener listener)
	{
		observers.addObserver(listener);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeUpdateListener(StoreUpdateListener listener)
	{
		observers.addObserver(listener);
	}
}
