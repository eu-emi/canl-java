/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Timer;
import java.util.TimerTask;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
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
	protected final ObserversHandler observers;
	private Timer timer;
	private long updateInterval;
	
	public TrustAnchorStoreBase(Timer timer, long updateInterval, ObserversHandler observers)
	{
		this.timer = timer;
		this.observers = observers;
		this.updateInterval = updateInterval;
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

	protected void scheduleUpdate()
	{
		long updateInterval = getUpdateInterval(); 
		if (updateInterval > 0)
			timer.schedule(new TimerTask()
			{
				public void run()
				{
					try
					{
						if (getUpdateInterval() > 0)
							update();
						scheduleUpdate();
					} catch (RuntimeException e)
					{
						//here we are really screwed up - there is a bug and no way to report it
						e.printStackTrace();
					}
				}
			}, updateInterval);
	}

	/**
	 * implementation should update the contents of the trust anchor store.
	 * It need not to bother with scheduling.
	 */
	protected abstract void update();
	
	
	/**
	 * After calling this method no notification will be produced and subsequent
	 * updates won't be scheduled. 
	 */
	@Override
	public void dispose()
	{
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
			observers.notifyObservers(location, StoreUpdateListener.CA_CERT, Severity.WARNING, 
				new Exception(sb.toString()));
		} catch (CertificateNotYetValidException e)
		{
			StringBuilder sb = prepErrorMsgPfx(certificate, addSubject);
			sb.append(" is NOT YET VALID: ").append(e.getMessage());
			observers.notifyObservers(location, 
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
