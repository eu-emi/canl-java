/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.io.CharArrayReader;
import java.io.IOException;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * This class extends the {@link PEMParser} class from the BC library.
 * It is modified to use the provided PemObject (it is done to optimize the code:
 * pem is not read twice) as otherwise BC's parsers code would need to be copied. 
 * The reader is bootstraped with the data from the PemObject.
 * <p>
 * This class interface is the readObject method. 
 * <p>
 * This implementation overrides the 
 * {@link PEMParser} readPemObject method to return a provided {@link PemObject}. 
 * The Reader used by the {@link PEMParser} is not used.
 * 
 * @author K. Benedyczak
 */
public class CachedPEMReader extends PEMParser
{
	private static final char[] nullInput = new char[0];
	protected PemObject pem;
	
	public CachedPEMReader(PemObject pem)
	{
		super(new CharArrayReader(nullInput));
		this.pem = pem;
	}

	/**
	 * Generate BC's PemObject from the input stream. 
	 * @return the parsed PEM object
	 * @throws IOException
	 */
	@Override
	public PemObject readPemObject() throws IOException
	{
		return pem;
	}
}




