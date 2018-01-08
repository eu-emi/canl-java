/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.util.Timer;

import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.WeakTimerTask;

/**
 * Base implementation of Trust Anchor stores which load all certificates into memory. Provides support for
 * timed scheduling of trust anchor store refreshes (which can be disabled).
 *  
 * @author K. Benedyczak
 */
public abstract class TimedTrustAnchorStoreBase extends AbstractTrustAnchorStore 
{
	private Timer timer;
	
	public TimedTrustAnchorStoreBase(Timer timer, long updateInterval, ObserversHandler observers)
	{
		super(updateInterval, observers);
		this.timer = timer;
	}
	
	@Override
	public synchronized void setUpdateInterval(long newInterval)
	{
		long old = getUpdateInterval();
		super.setUpdateInterval(newInterval);
		if (old <= 0)
			scheduleUpdate();
	}

	protected void scheduleUpdate()
	{
		long updateInterval = getUpdateInterval(); 
		if (updateInterval > 0)
			timer.schedule(new AsyncTrustAnchorsUpdateTask(this), updateInterval);
	}

	/**
	 * implementation should update the contents of the trust anchor store.
	 * It need not to bother with scheduling.
	 */
	public abstract void update();
	
	
	/**
	 * After calling this method no notification will be produced and subsequent
	 * updates won't be scheduled. 
	 */
	@Override
	public void dispose()
	{
		setUpdateInterval(-1);
	}
	
	/**
	 * Important: static nested class, weak reference to the wrapper.
	 * @author K. Benedyczak
	 */
	private static class AsyncTrustAnchorsUpdateTask extends WeakTimerTask<TimedTrustAnchorStoreBase>
	{

		public AsyncTrustAnchorsUpdateTask(TimedTrustAnchorStoreBase partner)
		{
			super(partner);
		}

		@Override
		public void run()
		{
			TimedTrustAnchorStoreBase partner = partnerRef.get();
			if (partner == null)
				return; //the work is over
			try
			{
				if (partner.getUpdateInterval() > 0)
					partner.update();
				partner.scheduleUpdate();
			} catch (RuntimeException e)
			{
				//here we are really screwed up - there is a bug and no way to report it
				e.printStackTrace();
			}
		}
	}
}
