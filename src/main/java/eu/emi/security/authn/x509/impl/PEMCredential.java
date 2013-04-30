/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PasswordFinder;


import eu.emi.security.authn.x509.helpers.AbstractDelegatingX509Credential;
import eu.emi.security.authn.x509.helpers.AbstractX509Credential;
import eu.emi.security.authn.x509.helpers.ReaderInputStream;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Wraps certificate and private key stored in PEM format. 
 * @author K. Benedyczak
 */
public class PEMCredential extends AbstractDelegatingX509Credential
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Constructs the object from {@link InputStream} which can be used to read 
	 * a private key and certificate in PEM keystore format, i.e. the file must contain
	 * both certificates and a private key. See 
	 * {@link CertificateUtils#loadPEMKeystore(InputStream, char[], char[])}
	 * for details.
	 * 
	 * @param keystorePath file path with the PEM keystore 
	 * @param keyPasswd Password used to decrypt the key. May be null if the key 
	 * is not encrypted.
	 * @throws IOException if the stream can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 */
	public PEMCredential(String keystorePath, char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{
		this(new BufferedInputStream(new FileInputStream(keystorePath)), keyPasswd);
	}

	/**
	 * As {@link #PEMCredential(String, char[])} but this version allows for providing 
	 * decryption key only when needed.  
	 * @param keystorePath file path with the PEM keystore 
	 * @param pf object to retrieve password on demand.
	 * @throws IOException if the stream can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 * @since 1.1.0
	 */
	public PEMCredential(String keystorePath, PasswordFinder pf) 
		throws IOException, KeyStoreException, CertificateException
	{
		this(new BufferedInputStream(new FileInputStream(keystorePath)), pf);
	}

	/**
	 * Constructs the object from {@link InputStream} which can be used to read 
	 * a private key and certificate in PEM keystore format, i.e. the file must contain
	 * both certificates and a private key. See 
	 * {@link CertificateUtils#loadPEMKeystore(InputStream, char[], char[])}
	 * for details.
	 * <p>
	 * The stream is closed after constructing the object.
	 * </p>
	 * 
	 * @param keystoreStream InputStream which can be used to read the PEM keystore 
	 * @param keyPasswd Password used to decrypt the key. May be null if the key 
	 * is not encrypted.
	 * @throws IOException if the stream can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 */
	public PEMCredential(InputStream keystoreStream, char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{
		this(keystoreStream, CertificateUtils.getPF(keyPasswd));
	}

	/**
	 * As {@link #PEMCredential(InputStream, char[])} but this version allows for providing 
	 * decryption key only when needed.  
	 * 
	 * @param keystoreStream InputStream which can be used to read the PEM keystore 
	 * @param pf object to retrieve password on demand.
	 * @throws IOException if the stream can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 * @since 1.1.0
	 */
	public PEMCredential(InputStream keystoreStream, PasswordFinder pf) 
		throws IOException, KeyStoreException, CertificateException
	{
		KeyStore ks = CertificateUtils.loadPEMKeystore(keystoreStream, pf, 
				AbstractX509Credential.KEY_PASSWD);
		X509Certificate[] certChain = CertificateUtils.convertToX509Chain(
				ks.getCertificateChain(CertificateUtils.DEFAULT_KEYSTORE_ALIAS));
		PrivateKey pk;
		try
		{
			pk = (PrivateKey)ks.getKey(CertificateUtils.DEFAULT_KEYSTORE_ALIAS,
					AbstractX509Credential.KEY_PASSWD);
		} catch (Exception e)
		{
			throw new RuntimeException("Can't get key from the generated keystore, bug?", e);
		}
		delegate = new KeyAndCertCredential(pk, certChain);
	}
	
	/**
	 * Constructs the object from two {@link InputStream}s which can be used to read 
	 * a private key and certificate in PEM format.
	 * <p>
	 * The streams are closed after constructing the object.
	 * </p>
	 * 
	 * @param privateKeyStream InputStream which can be used to read the private key in PEM format 
	 * @param certificateStream certificate in PEM format InputStream
	 * @param keyPasswd Password used to decrypt the key. May be null if the key 
	 * is not encrypted.
	 * @throws IOException if any of the streams can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 */
	public PEMCredential(InputStream privateKeyStream, InputStream certificateStream, char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{
		this(privateKeyStream, certificateStream, CertificateUtils.getPF(keyPasswd));
	}
	
	/**
	 * As {@link #PEMCredential(InputStream, InputStream, char[])} but password is retrieved on demand.
	 *  
	 * @param privateKeyStream InputStream which can be used to read the private key in PEM format 
	 * @param certificateStream certificate in PEM format InputStream
	 * @param pf object to retrieve password on demand.
	 * @throws IOException if any of the streams can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 * @since 1.1.0
	 */
	public PEMCredential(InputStream privateKeyStream, InputStream certificateStream, PasswordFinder pf) 
		throws IOException, KeyStoreException, CertificateException
	{
		init(privateKeyStream, certificateStream, pf);
	}
	
	/**
	 * Constructs the object from two {@link Reader}s which can be used to read 
	 * a private key and certificate in PEM format.
	 * <p>
	 * The streams are closed after constructing the object.
	 * </p>
	 * @param privateKeyReader Reader which can be used to read the PEM private key 
	 * @param certificateReader certificate file Reader
	 * @param keyPasswd Password used to decrypt the key. May be null if the key 
	 * is not encrypted.
	 * @throws IOException if any of files can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 */
	public PEMCredential(Reader privateKeyReader, Reader certificateReader, char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{
		this(privateKeyReader, certificateReader, CertificateUtils.getPF(keyPasswd));
	}
	
	/**
	 * As {@link #PEMCredential(Reader, Reader, char[])} but password is retrieved on demand.
	 * 
	 * @param privateKeyReader Reader which can be used to read the PEM private key 
	 * @param certificateReader certificate file Reader
	 * @param pf object to retrieve password on demand.
	 * @throws IOException if any of files can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
 	 * @since 1.1.0
	 */
	public PEMCredential(Reader privateKeyReader, Reader certificateReader, PasswordFinder pf) 
		throws IOException, KeyStoreException, CertificateException
	{
		InputStream pkIs = new ReaderInputStream(privateKeyReader, CertificateUtils.ASCII);
		InputStream ccIs = new ReaderInputStream(certificateReader, CertificateUtils.ASCII);
		init(pkIs, ccIs, pf);
	}
	
	/**
	 * Constructs the object from two files containing private key and certificate in
	 * PEM format.
	 * <p>
	 * The streams are closed after constructing the object.
	 * </p>
	 * 
	 * @param keyPath private key file path
	 * @param certificatePath certificate file path
	 * @param keyPasswd Password used to decrypt the key. May be null if the key 
	 * is not encrypted.
	 * @throws IOException if any of files can not be read
	 * @throws KeyStoreException if private key can not be parsed or decrypted
	 * @throws CertificateException if certificate can not be parsed
	 */
	public PEMCredential(String keyPath, String certificatePath, char[] keyPasswd) 
		throws IOException, KeyStoreException, CertificateException
	{

            InputStream privateKeyStream = null;
            InputStream certificateStream = null;
            try {
                privateKeyStream = new FileInputStream(keyPath);
                certificateStream = new FileInputStream(certificatePath);
                PasswordFinder pf = CertificateUtils.getPF(keyPasswd);
                init(privateKeyStream, certificateStream, pf);
            } finally {
                if (privateKeyStream != null) {
                    try {
                        privateKeyStream.close();
                    } catch (IOException consumed) {
                    }
                }
                if (certificateStream != null) {
                    try {
                        certificateStream.close();
                    } catch (IOException consumed) {
                    }
                }
            }
	}

	
	private void init(InputStream privateKeyStream, InputStream certificateStream, 
			PasswordFinder pf) throws IOException, KeyStoreException, CertificateException
	{
		X509Certificate []chain = CertificateUtils.loadCertificateChain(
				certificateStream, Encoding.PEM);
		PrivateKey pk = CertificateUtils.loadPEMPrivateKey(privateKeyStream, pf);
		privateKeyStream.close();
		delegate = new KeyAndCertCredential(pk, chain);
	}
}
