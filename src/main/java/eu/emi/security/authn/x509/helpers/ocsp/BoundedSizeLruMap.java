/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.util.LinkedHashMap;
import java.util.Map;

public class BoundedSizeLruMap<S, T> extends LinkedHashMap<S, T>
{
	private final int maxEntries;

	public BoundedSizeLruMap(int maxEntries)
	{
		super(20, 0.75f, true);
		this.maxEntries = maxEntries;
	}

	@Override
	protected boolean removeEldestEntry(Map.Entry<S, T> eldest)
	{
		return size() > maxEntries;
	}
}