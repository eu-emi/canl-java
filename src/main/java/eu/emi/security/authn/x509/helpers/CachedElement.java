/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

/**
 * Cached element is a container of an arbitrary object, 
 * enriched with a creation timestamp.
 * 
 * @author K. Benedyczak
 */
public class CachedElement<T>
{
	private long creationTs;
	private T element;

	public CachedElement(T element)
	{
		this.creationTs = System.currentTimeMillis();
		this.element = element;
	}

	public long getCreationTs()
	{
		return creationTs;
	}

	public T getElement()
	{
		return element;
	}
	
	public boolean isExpired(long ttl)
	{
		return System.currentTimeMillis() > ttl + creationTs;
	}
}
