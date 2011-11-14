/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import org.bouncycastle.asn1.DEREncodable;

/**
 * Stores DER form of a certificate attribute value with its OID. 
 * 
 * @author K. Benedyczak
 */
public class OidAndValue<T extends DEREncodable> implements Cloneable
{
	protected T value;
	protected String oid;
	
	protected OidAndValue()
	{
	}
	
	public OidAndValue(String oid, T value)
	{
		this.value = value;
		this.oid = oid;
	}
	public T getValue()
	{
		return value;
	}
	public void setValue(T value)
	{
		this.value = value;
	}
	public String getOid()
	{
		return oid;
	}
	public void setOid(String oid)
	{
		this.oid = oid;
	}
	
	public OidAndValue<T> clone()
	{
		return new OidAndValue<T>(oid, value);
	}
}
