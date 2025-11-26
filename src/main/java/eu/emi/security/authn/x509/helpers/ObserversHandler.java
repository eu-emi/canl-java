/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;

/**
 * Thread safe class maintaining a collection of {@link StoreUpdateListener}s. 
 *
 * @author K. Benedyczak
 */
public class ObserversHandler
{
	private Set<StoreUpdateListener> observers;

	public ObserversHandler()
	{
		this(null);
	}
	
	public ObserversHandler(Collection<? extends StoreUpdateListener> initialObservers)
	{
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
	public synchronized void addObserver(StoreUpdateListener listener)
	{
		observers.add(listener);
	}
	
	/**
	 * Unregisters a previously registered CA or CRL update listener. If the listener
	 * was not registered then the method does nothing. 
	 * @param listener to be unregistered
	 */
	public synchronized void removeObserver(StoreUpdateListener listener)
	{
		observers.remove(listener);
	}
	
	public synchronized void notifyObservers(String url, String type, Severity level, Exception e)
	{
		for (StoreUpdateListener observer: observers)
			observer.loadingNotification(url, type, level, e);
	}
	
	public synchronized void removeAllObservers()
	{
		observers.clear();
	}
}
