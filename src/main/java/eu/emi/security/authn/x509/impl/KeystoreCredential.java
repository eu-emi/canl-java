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
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import eu.emi.security.authn.x509.helpers.AbstractX509Credential;

/**
 * Wraps a Java KeyStore in form suitable for use in JSSE.
 * 
 * @author K. Benedyczak
 */
public class KeystoreCredential extends AbstractX509Credential
{
	/**
	 * Reads a Java KeyStore to provide an interface suitable to use it
	 * in JSSE.
	 * 
	 * @param keystorePath keystore path
	 * @param storePasswd keystore password
	 * @param keyPasswd private key password
	 * @param keyAlias private key alias
	 * @param storeType type of the keystore, "JKS" or "PKCS12"
	 * @throws IOException if the keystore can not be read
	 * @throws KeyStoreException if the keystore can not be parsed or if passwords are incorrect
	 */
	public KeystoreCredential(String keystorePath, char[] storePasswd, 
			char[] keyPasswd, String keyAlias, String storeType) 
			throws IOException, KeyStoreException
	{
		KeyStore loaded = loadKeystore(keystorePath, storePasswd, storeType);
		checkKeystore(loaded, keyPasswd, keyAlias);
		createSingleKeyView(loaded, keyAlias, keyPasswd);
	}

	
	protected KeyStore loadKeystore(String keystorePath, char[] storePasswd, String storeType) 
			throws KeyStoreException, IOException
	{
		KeyStore ks = KeyStore.getInstance(storeType);
		InputStream is = new BufferedInputStream(new FileInputStream(new File(keystorePath)));
		try
		{
			ks.load(is, storePasswd);
			is.close();
			return ks;
		} catch (NoSuchAlgorithmException e)
		{
			throw new KeyStoreException("Keystore has contents using " +
					"an unsupported algorithm", e);
		} catch (CertificateException e)
		{
			throw new KeyStoreException("Keystore certificate is invalid", e);
		}
		
	}
	
	protected void checkKeystore(KeyStore ks, char[] keyPasswd, String keyAlias) throws KeyStoreException
	{
		try
		{
			if (!ks.containsAlias(keyAlias))
				throw new KeyStoreException("Key alias >" + keyAlias + 
						"< does not exist in the keystore");
			Key k = ks.getKey(keyAlias, keyPasswd);
			if (k == null)
				throw new KeyStoreException("Key alias >" + keyAlias + 
						"< is not an alias of a key entry, but an alias of a certificate entry");
			if (!(k instanceof PrivateKey))
				throw new KeyStoreException("Key under the alias >" + keyAlias + 
						"< is not a PrivateKey but " + k.getClass().getName());
		} catch (UnrecoverableKeyException e)
		{
			throw new KeyStoreException("Key's password seems to be incorrect", e);
		} catch (NoSuchAlgorithmException e)
		{
			throw new KeyStoreException("Key is encrypted or uses an unsupported algorithm", e);
		}		
	}
	
	protected void createSingleKeyView(KeyStore original, String alias, char[] password)
	{
		try
		{
			ks = KeyStore.getInstance("JKS");
			ks.load(null);
			Key key = original.getKey(alias, password);
			Certificate []chain = original.getCertificateChain(alias);
			ks.setKeyEntry(ALIAS, key, KEY_PASSWD, chain);
		} catch (Exception e)
		{
			throw new RuntimeException("Got error when loading data from the" +
					"correct original keystore - this is most probably a bug", e);
		}
	}
}
