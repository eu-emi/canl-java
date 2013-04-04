/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.lang.ref.WeakReference;
import java.util.TimerTask;

/**
 * This class holds a partner of the TimerTask reference as weak one. This allows to have weak association:
 * the partner's object can be disposed without being blocked by a strong reference of the timer.
 * 
 * <p>
 * IMPORTANT! Never use this class as base for an inner or anonymous class. This will create an implicit 
 * strong reference to the wrapping partner, so it won't be disposed until the timer task is cancelled.
 *  
 * @author K. Benedyczak
 */
public abstract class WeakTimerTask<T> extends TimerTask
{
	protected WeakReference<T> partnerRef;
	
	public WeakTimerTask(T partner)
	{
		partnerRef = new WeakReference<T>(partner);
	}
}
