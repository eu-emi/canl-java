/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.crl;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;

/**
 * Contains methods which are common to all CertStore providing CRLs for this library
 * @author K. Benedyczak
 */
public abstract class AbstractCRLCertStoreSpi extends CertStoreSpi
{
	private Set<StoreUpdateListener> observers;
	
	public AbstractCRLCertStoreSpi(CertStoreParameters params, 
			Collection<? extends StoreUpdateListener> initialObservers)
			throws InvalidAlgorithmParameterException
	{
		super(params);
		observers = new HashSet<StoreUpdateListener>();
		if (initialObservers != null)
			observers.addAll(initialObservers);
	}

	/**
	 * Registers a listener which can react to errors found during refreshing 
	 * of the trust material: trusted CAs or CRLs. This method is useful only if
	 * the implementation supports updating of CAs or CRLs, otherwise the listener
	 * will not be invoked.  
	 * 
	 * @param listener to be registered
	 */
	public void addUpdateListener(StoreUpdateListener listener)
	{
		synchronized(observers)
		{
			observers.add(listener);
		}
	}
	
	/**
	 * Unregisters a previously registered CA or CRL update listener. If the listener
	 * was not registered then the method does nothing. 
	 * @param listener to be unregistered
	 */
	public void removeUpdateListener(StoreUpdateListener listener)
	{
		synchronized(observers)
		{
			observers.remove(listener);
		}
	}
	
	protected void notifyObservers(String url, Severity level, Exception e)
	{
		synchronized(observers)
		{
			for (StoreUpdateListener observer: observers)
				observer.loadingNotification(url, StoreUpdateListener.CRL,
						level, e);
		}
	}
	
	protected void removeAllObservers()
	{
		synchronized(observers)
		{
			observers.clear();
		}
	}
	
	public abstract void dispose();
}
