/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.io.CharArrayReader;
import java.io.IOException;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * This class extends the {@link PEMReader} class from the BC library.
 * It is modified to use the provided PemObject (it is done to optimize the code:
 * pem is not read twice) as otherwise BC's parsers code would need to be copied. 
 * The reader is bootstraped with the data from the PemObject.
 * <p>
 * This class interface is the readObject method. 
 * <p>
 * This implementation overrides the 
 * {@link PemReader} readPemObject method to return a provided {@link PemObject}. 
 * The Reader used by the {@link PemReader} is not used.
 * 
 * @author K. Benedyczak
 */
public class CachedPEMReader extends PEMReader
{
	protected PemObject pem;
	protected PasswordFinder myPFinder;
	
	public CachedPEMReader(PemObject pem, PasswordFinder pFinder)
	{
		super(new CharArrayReader(new char[0]), pFinder);
		this.pem = pem;
		this.myPFinder = pFinder;
	}

	public CachedPEMReader(PemObject pem)
	{
		super(new CharArrayReader(new char[0]), null);
		this.pem = pem;
		this.myPFinder = null;
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




