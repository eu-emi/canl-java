/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Base implementation of Trust Anchor stores. Provides two functions:
 *  - timed scheduling of trust anchor store refreshes (which can be disabled)
 *  - observers support
 *  
 * @author K. Benedyczak
 */
public abstract class TrustAnchorStoreBase implements TrustAnchorStore 
{
	private Set<StoreUpdateListener> observers;
	private Timer timer;
	private long updateInterval;
	
	public TrustAnchorStoreBase(Timer timer, long updateInterval, 
			Collection<? extends StoreUpdateListener> listeners)
	{
		this.timer = timer;
		observers = new LinkedHashSet<StoreUpdateListener>();
		if (listeners != null)
			observers.addAll(listeners);
		this.updateInterval = updateInterval;
		scheduleUpdate();
	}
	
	public synchronized long getUpdateInterval()
	{
		return updateInterval;
	}
	
	public synchronized void setUpdateInterval(long newInterval)
	{
		long old = getUpdateInterval();
		updateInterval = newInterval;
		if (old <= 0)
			scheduleUpdate();
	}

	private void scheduleUpdate()
	{
		if (getUpdateInterval() > 0)
			timer.schedule(new TimerTask()
			{
				public void run()
				{
					if (getUpdateInterval() > 0)
						update();
					scheduleUpdate();
				}
			}, getUpdateInterval());
	}

	/**
	 * implementation should update the contents of the trust anchor store.
	 * It need not to bother with scheduling.
	 */
	protected abstract void update();
	
	
	
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
	
	protected void notifyObservers(String url, String type, 
			Severity level, Exception e)
	{
		synchronized(observers)
		{
			for (StoreUpdateListener observer: observers)
				observer.loadingNotification(url, type, level, e);
		}
	}
	
	/**
	 * After calling this method no notification will be produced and subsequent
	 * updates won't be scheduled. However one next update may be run.
	 */
	public void dispose()
	{
		synchronized(observers)
		{
			observers.clear();
		}
		setUpdateInterval(-1);
	}
	
	protected void checkValidity(String location, X509Certificate certificate, boolean addSubject)
	{
		try
		{
			certificate.checkValidity();
		} catch (CertificateExpiredException e)
		{
			StringBuilder sb = prepErrorMsgPfx(certificate, addSubject);
			sb.append(" is EXPIRED: ").append(e.getMessage());
			notifyObservers(location, StoreUpdateListener.CA_CERT, Severity.WARNING, 
				new Exception(sb.toString()));
		} catch (CertificateNotYetValidException e)
		{
			StringBuilder sb = prepErrorMsgPfx(certificate, addSubject);
			sb.append(" is NOT YET VALID: ").append(e.getMessage());
			notifyObservers(location, 
				StoreUpdateListener.CA_CERT, Severity.WARNING, 
				new Exception(sb.toString()));
		} 
	}
	
	private static StringBuilder prepErrorMsgPfx(X509Certificate certificate, boolean addSubject)
	{
		StringBuilder sb = new StringBuilder();
		sb.append("Trusted CA certificate");
		if (addSubject)
		{
			sb.append(" with subject ");
			sb.append(X500NameUtils.getReadableForm(
				certificate.getSubjectX500Principal()));
		}
		return sb;
	}
}
