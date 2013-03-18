/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;

import eu.emi.security.authn.x509.helpers.AbstractX509Credential;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.KeyStoreHelper;

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
	 * @param keyAlias private key alias or null. In case of null, alias will be autodetected,
	 * however this will work only it the keystore contains exactly one key entry. 
	 * @param storeType type of the keystore, "JKS" or "PKCS12". null value is forbidden, 
	 * but if autodetection is desired the static autodetectType() method of this can be used. 
	 * @throws IOException if the keystore can not be read
	 * @throws KeyStoreException if the keystore can not be parsed or if passwords are incorrect
	 */
	public KeystoreCredential(String keystorePath, char[] storePasswd, 
			char[] keyPasswd, String keyAlias, String storeType) 
			throws IOException, KeyStoreException
	{
		KeyStore loaded = loadKeystore(keystorePath, storePasswd, storeType);
		keyAlias = checkKeystore(loaded, keyPasswd, keyAlias);
		createSingleKeyView(loaded, keyAlias, keyPasswd);
	}

	
	protected KeyStore loadKeystore(String keystorePath, char[] storePasswd, String storeType) 
			throws KeyStoreException, IOException
	{
		KeyStore ks = KeyStoreHelper.getInstanceForCredential(storeType);
		InputStream is = new BufferedInputStream(new FileInputStream(new File(keystorePath)));
		try
		{
			ks.load(is, storePasswd);
			return ks;
		} catch (NoSuchAlgorithmException e)
		{
			throw new KeyStoreException("Keystore contents is using " +
					"an unsupported algorithm", e);
		} catch (CertificateException e)
		{
			throw new KeyStoreException("Keystore certificate is invalid", e);
		}  catch (IOException e)
		{
			if (e.getCause() != null && e.getCause() instanceof BadPaddingException)
				throw new KeyStoreException("Keystore key password is invalid or the keystore is corrupted.", e);
			throw e;
		} finally 
		{
			is.close();
		}
		
	}
	
	protected String checkKeystore(KeyStore ks, char[] keyPasswd, String keyAlias) throws KeyStoreException
	{
		try
		{
			if (keyAlias == null)
				keyAlias = getDefaultKeyAlias(ks);
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
			Certificate c = ks.getCertificate(keyAlias);
			if (c == null)
				throw new KeyStoreException("There is no certificate associated with " +
						"the key under the alias >" + keyAlias + "<");
			CertificateHelpers.checkKeysMatching((PrivateKey) k, c.getPublicKey());
			return keyAlias;
		} catch (UnrecoverableKeyException e)
		{
			throw new KeyStoreException("Key's password seems to be incorrect", e);
		} catch (NoSuchAlgorithmException e)
		{
			throw new KeyStoreException("Key is encrypted or uses an unsupported algorithm", e);
		} catch (InvalidKeyException e)
		{
			throw new KeyStoreException("Key and certificate in the keystore are not matching", e);
		}		
	}
	
	protected String getDefaultKeyAlias(KeyStore keystore) throws KeyStoreException
	{
		Enumeration<String> e = keystore.aliases();
		String ret = null;
		while (e.hasMoreElements())
		{
			String a = e.nextElement();
			if (keystore.isKeyEntry(a))
			{
				if (ret == null)
					ret = a;
				else
					throw new KeyStoreException("Key alias was not " +
							"provided and the keystore contains more then one key entry: " 
							+ a + " and " + ret);
			}
		}
		if (ret == null)
			throw new KeyStoreException("The keystore doesn't contain any key entry");
		return ret;
	}

	
	protected void createSingleKeyView(KeyStore original, String alias, char[] password)
	{
		try
		{
			ks = KeyStoreHelper.getInstanceForCredential("JKS");
			ks.load(null);
			Key key = original.getKey(alias, password);
			Certificate []chain = original.getCertificateChain(alias);
			ks.setKeyEntry(ALIAS, key, KEY_PASSWD, chain);
		} catch (Exception e)
		{
			throw new RuntimeException("Got error when loading data from the " +
					"correct original keystore - this is most probably a bug", e);
		}
	}
	
	/**
	 * Tries to autodetect keystore type.
	 * @param ksPath
	 * @param ksPassword
	 * @return Detected type
	 * @throws IOException if error occurred when reading the file
	 * @throws KeyStoreException if autodetection failed
	 *  
	 */
	public static String autodetectType(String ksPath, char[] ksPassword) throws IOException,
		KeyStoreException
	{
		File file = new File(ksPath);
		if (!file.exists())
			throw new FileNotFoundException("Keystore file " + 
					ksPath + " does not exist");
		if (!file.isFile())
			throw new IOException("Keystore specified with " + 
					ksPath + " is not a file (is directory?)");
		if (!file.canRead())
			throw new IOException("Keystore specified with " + 
					ksPath + " is not readable");
		String guess;
		if (ksPath.endsWith("p12") || ksPath.endsWith("pkcs") || ksPath.endsWith("pkcs12"))
			guess = "PKCS12";
		else
			guess = "JKS";
		
		if (tryLoadKs(guess, ksPath, ksPassword))
			return guess;
		
		if (guess.equals("JKS"))
			guess = "PKCS12";
		else
			guess = "JKS";

		if (tryLoadKs(guess, ksPath, ksPassword))
			return guess;

		throw new KeyStoreException("Autodetection of keystore type failed. " +
				"Most probably it is not a valid JKS or PKCS12 file.");
	}

	private static boolean tryLoadKs(String type, String ksPath, char[] ksPassword) 
	{
		InputStream is = null;
		try
		{
			KeyStore ks = KeyStoreHelper.getInstanceForCredential(type);
			is = new BufferedInputStream(new FileInputStream(ksPath));
			ks.load(is, ksPassword);
		} catch (IOException e)
		{
			if (e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException)
			{
				//password is wrong but it seems that type correct
				return true;
			}
			return false;
		} catch (Exception e)
		{
			return false;
		} finally
		{
			if (is != null)
				try
				{
					is.close();
				} catch (IOException e)
				{
					//we did our best
				}
		}
		return true;
	}

}