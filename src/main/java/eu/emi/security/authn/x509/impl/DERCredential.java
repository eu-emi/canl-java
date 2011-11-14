/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.helpers.AbstractDelegatingX509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Wraps certificate and private key stored in DER format.
 * 
 * @author K. Benedyczak
 */
public class DERCredential extends AbstractDelegatingX509Credential
{
	/**
	 * Constructs the object from two {@link InputStream}s which can be used to read 
	 * a private key and certificate in DER PKCS8 format.
	 * <p>
	 * The streams are closed after constructing the object.
	 * </p>
	 * 
	 * @param privateKeyStream InputStream which can be used to read the private key in DER format 
	 * @param certificateStream certificate input stream in DER format
	 * @param keyPasswd key password or null if the key is not encrypted
	 * @throws IOException if any of streams can not be read
	 * @throws KeyStoreException if private key can not be parsed
	 * @throws CertificateException if certificate can not be parsed
	 */
	public DERCredential(InputStream privateKeyStream, InputStream certificateStream, 
			char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{
		X509Certificate []chain = CertificateUtils.loadCertificateChain(
				certificateStream, Encoding.DER);
		PrivateKey pk = CertificateUtils.loadPrivateKey(privateKeyStream, 
				Encoding.DER, keyPasswd);

		privateKeyStream.close();
		certificateStream.close();
		
		delegate = new KeyAndCertCredential(pk, chain);
	}

	
	/**
	 * Constructs the object from two files containing private key and certificate in
	 * DER PKCS8 format.
	 * <p>
	 * The streams are closed after constructing the object.
	 * </p>
	 * 
	 * @param keyPath private key file path in DER format
	 * @param certificatePath certificate file path in DER format
	 * @param keyPasswd key password or null if the key is not encrypted
	 * @throws IOException if any of files can not be read
	 * @throws KeyStoreException if private key can not be parsed
	 * @throws CertificateException if certificate can not be parsed
	 */
	public DERCredential(String keyPath, String certificatePath, char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{
		this(new BufferedInputStream(new FileInputStream(new File(keyPath))),
				new BufferedInputStream(new FileInputStream(new File(certificatePath))),
				keyPasswd);
	}
}
