/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 * 
 * Parts of this class are derived from the glite.security.util-java module, 
 * copyrighted as follows:
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004. See
 * http://www.eu-egee.org/partners/ for details on the copyright holders.
 */
package eu.emi.security.authn.x509.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import eu.emi.security.authn.x509.helpers.CachedPEMReader;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.CertificateHelpers.PEMContentsType;
import eu.emi.security.authn.x509.helpers.CharArrayPasswordFinder;
import eu.emi.security.authn.x509.helpers.FlexiblePEMReader;
import eu.emi.security.authn.x509.helpers.PKCS8DERReader;

/**
 * Utility class with methods simplifying typical certificate related operations.
 * 
 * @author K. Benedyczak
 * @author J. Hahkala
 */
public class CertificateUtils
{
	static 
	{
		configureSecProvider();
	}
	
	/**
	 * Definition of the encoding that can be used for reading or writing 
	 * certificates or keys.
	 */
	public static enum Encoding {PEM, DER}
	
	public static final String DEFAULT_KEYSTORE_ALIAS = "default";
	
	public static final Charset ASCII = Charset.forName("US-ASCII");
	
	public static void configureSecProvider()
	{
		if (Security.getProvider("BC") == null)
			Security.addProvider(new BouncyCastleProvider());
	}
	
	/**
	 * Performs a trivial conversion by use of casting of a Certificate array
	 * into X509Certificate array 
	 * @param chain to convert
	 * @return converted chain
	 * @throws ClassCastException if at least one entry in the source chain is not
	 * an {@link X509Certificate}
	 */
	public static X509Certificate[] convertToX509Chain(Certificate []chain) 
		throws ClassCastException
	{
		X509Certificate[] ret = new X509Certificate[chain.length];
		for (int i=0; i<chain.length; i++)
			ret[i] = (X509Certificate) chain[i];
		return ret;
	}
	
	/**
	 * Produces a human readable text representation of the provided certificate.
	 * It uses {@link X509Formatter} internally.
	 * @param cert input certificate
	 * @param mode controls how detailed the string representation should be 
	 * @return the text representation
	 */
	public static String format(X509Certificate cert, FormatMode mode)
	{
		X509Formatter formatter = new X509Formatter(mode);
		return formatter.format(cert);
	}

	/**
	 * Produces a human readable text representation of the provided certificate chain. 
	 * It uses {@link X509Formatter} internally.
	 * @param certChain input certificates
	 * @param mode controls how detailed the string representation should be 
	 * @return the text representation
	 */
	public static String format(X509Certificate[] certChain, FormatMode mode)
	{
		X509Formatter formatter = new X509Formatter(mode);
		return formatter.format(certChain);
	}

	
	/**
	 * Loads a single certificate from the provided input stream. 
	 * @param is input stream to read encoded certificate from
	 * @param format encoding type
	 * @return loaded certificate
	 * @throws IOException if certificate can not be read or parsed
	 */
	public static X509Certificate loadCertificate(InputStream is, Encoding format) 
			throws IOException
	{
		X509Certificate[] certs = loadCertificateChain(is, format);
		if (certs.length != 1)
			throw new IOException("The PEM contains more than one certificate");
		return certs[0];
	}

	/**
	 * Loads a private key from the provided input stream. The input stream must be encoded
	 * in the PKCS8 format (PEM or DER). Additionally in case of PEM encoding the legacy 
	 * OpenSSL format for storing private keys is supported. Such PEM header names
	 * has algorithm {RSA|DSA|EC} placed before the PRIVATE KEY string.
	 * <p>
	 * Currently supported key encryption algorithms are DES and 3 DES. RC2 is unsupported.
	 * @param is input stream to read encoded key from
	 * @param format encoding type (PEM or DER)
	 * @param password key's encryption password (can be null is file is not encrypted)
	 * @return loaded key
	 * @throws IOException if key can not be read or parsed
	 */
	public static PrivateKey loadPrivateKey(InputStream is, Encoding format, 
			char[] password) throws IOException
	{
		if (format.equals(Encoding.PEM))
		{
			PasswordFinder pf = (password == null) ? null : 
				new CharArrayPasswordFinder(password);
			Reader reader = new InputStreamReader(is, Charset.forName("US-ASCII"));
			FlexiblePEMReader pemReader = new FlexiblePEMReader(reader, pf);
			Object ret = pemReader.readObject();
			if (ret instanceof PrivateKey)
				return (PrivateKey) ret;
			if (ret instanceof KeyPair)
			{
				KeyPair kp = (KeyPair) ret;
				return kp.getPrivate();
			}
			throw new IOException("The PEM does not contain a private key, " +
					"it was parsed as " + ret.getClass().getName());
		} else
			return loadDERPrivateKey(is, password);
	}

	private static PrivateKey parsePEMPrivateKey(PemObject pem, char[] password) 
			throws IOException
	{
		PasswordFinder pf = (password == null) ? null : 
			new CharArrayPasswordFinder(password);
		CachedPEMReader pemReader = new CachedPEMReader(pem, pf);
		Object ret = pemReader.readObject();
		if (ret instanceof PrivateKey)
			return (PrivateKey) ret;
		if (ret instanceof KeyPair)
		{
			KeyPair kp = (KeyPair) ret;
			return kp.getPrivate();
		}
		throw new IOException("The PEM input does not contain a private key, " +
				"it was parsed as " + ret.getClass().getName());
	}

	
	private static PrivateKey loadDERPrivateKey(InputStream is, char[] password) 
			throws IOException
	{
		PasswordFinder pf = (password == null) ? null : 
			new CharArrayPasswordFinder(password);
		PKCS8DERReader derReader = new PKCS8DERReader(is, pf);
		Object ret = derReader.readObject();
		if (ret instanceof PrivateKey)
			return (PrivateKey) ret;
		throw new IOException("The DER input does not contain a private key, " +
				"it was parsed as " + ret.getClass().getName());
	}
	
	/**
	 * Loads a chain of certificates from the provided input stream.
	 * @param is input stream to read encoded certificates from
	 * @param format encoding type
	 * @return loaded certificates array
	 * @throws IOException if certificates can not be read or parsed
	 */
	public static X509Certificate[] loadCertificateChain(InputStream is, Encoding format) throws IOException
	{
		InputStream realIS = is;
		if (format.equals(Encoding.PEM))
		{
			boolean readOne = false;
			ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
			Reader br = new InputStreamReader(is, ASCII);
			FlexiblePEMReader pemReader = new FlexiblePEMReader(br);
			do
			{
				PemObject pem = pemReader.readPemObject();
				if (pem == null && readOne == false)
					throw new IOException("PEM data not found in the stream and its end was reached");
				if (pem == null)
					break;
				PEMContentsType type = CertificateHelpers.getPEMType(pem.getType());
				if (!type.equals(PEMContentsType.CERTIFICATE))
					throw new IOException("Expected PEM encoded certificate but found: " + type);
				readOne = true;
				buffer.write(pem.getContent());
			} while (true);
			realIS = new ByteArrayInputStream(buffer.toByteArray());
		}
		return loadDERCertificateChain(realIS);
	}

	private static X509Certificate[] loadDERCertificateChain(InputStream is) throws IOException
	{
		Collection<? extends Certificate> certs = CertificateHelpers.readDERCertificates(is);
		Iterator<? extends Certificate> iterator = certs.iterator();
		X509Certificate []ret = new X509Certificate[certs.size()];
		for (int i=0; i<ret.length; i++)
		{
			Certificate c = iterator.next();
			if (!(c instanceof X509Certificate))
				throw new IOException("The PEM contains a certificate which is not a " +
						"X.509Certificate, it is " + c.getClass().getName());
			ret[i] = (X509Certificate) c;
		}
		return ret;
	}
	
	/**
	 * Loads certificates and private keys from the PEM input stream 
	 * (usually from file). Order of entries is not relevant. However it is assumed 
	 * that the input contains:
	 * <ol>
	 *  <li> one private key K,
	 *  <li> one certificate C corresponding to the private key K,
	 *  <li> zero or more certificates that if present form a 
	 *  chain of the certificate C. 
	 * </ol>
	 * If more then one certificate is found then this method tries to sort them to
	 * form a consistent chain (inability to do so is thrown as an exception) and assumes
	 * that the last certificate in chain is the user's certificate corresponding 
	 * to the private key.
	 *  
	 * @param is input stream to read from
	 * @param password private key's encryption password or null if key is not encrypted.
	 * @param ksPassword password which is used to encrypt the private key in the keystore. 
	 * Can not be null.
	 * @return KeyStore with one private key typed entry, with alias 
	 * {@link #DEFAULT_KEYSTORE_ALIAS} of the JKS type. If password is != null then it is also
	 * used to crypt the key in the keystore. If it is null then #
	 * @throws IOException if input can not be read or parsed
	 */
	public static KeyStore loadPEMKeystore(InputStream is, char[] password, char[] ksPassword) throws IOException
	{
		PrivateKey pk = null;
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		Reader br = new InputStreamReader(is, ASCII);
		FlexiblePEMReader pemReader = new FlexiblePEMReader(br);
		do
		{
			PemObject pem = pemReader.readPemObject();
			if (pem == null)
				break;
			PEMContentsType type = CertificateHelpers.getPEMType(pem.getType());
			if (type.equals(PEMContentsType.PRIVATE_KEY) || type.equals(PEMContentsType.LEGACY_OPENSSL_PRIVATE_KEY))
			{
				if (pk != null)
					throw new IOException("Multiple private keys were found");
				pk = parsePEMPrivateKey(pem, password);
			} else if (type.equals(PEMContentsType.CERTIFICATE))
			{
				X509Certificate[] certs = loadDERCertificateChain(
						new ByteArrayInputStream(pem.getContent()));
				for (X509Certificate cert: certs)
					certChain.add(cert);
			} else
			{
				throw new IOException("Unsupported PEM object found in the input: " + type);
			}
		} while (true);
		
		Certificate []chain = CertificateHelpers.sortChain(certChain);
		
		KeyStore ks;
		try
		{
			ks = KeyStore.getInstance("JKS");
			ks.load(null, null);
			ks.setKeyEntry(DEFAULT_KEYSTORE_ALIAS, pk, ksPassword, chain);
		} catch (KeyStoreException e)
		{
			throw new IOException("Can't setup the JKS keystore", e);
		} catch (NoSuchAlgorithmException e)
		{
			throw new IOException("Can't setup the JKS keystore", e);
		} catch (CertificateException e)
		{
			throw new IOException("Can't setup the JKS keystore", e);
		}
		return ks;
	}

	/**
	 * Saves the provided certificate to the output file, using the requested encoding.
	 * @param os where to write the encoded certificate to 
	 * @param cert certificate to save
	 * @param format format to use
	 * @throws IOException if the data can not be written 
	 */
	public static void saveCertificate(OutputStream os, X509Certificate cert, 
			Encoding format) throws IOException
	{
		if (format.equals(Encoding.PEM))
		{
			PEMWriter writer = new PEMWriter(new OutputStreamWriter(os, ASCII));
			writer.writeObject(cert);
			writer.flush();
		} else
		{
			try
			{
				os.write(cert.getEncoded());
			} catch (CertificateEncodingException e)
			{
				throw new IOException("Can't encode the " +
						"certificate into ASN.1 DER format", e);
			}
			os.flush();
		}
	}

	/**
	 * Saves the provided private key to the output file, using the requested encoding.
	 * @param os where to write the encoded key to 
	 * @param pk key to save
	 * @param format format to use
	 * @param encryptionAlg encryption algorithm to be used.
	 * See {@link PKCS8Generator} constants for available names. Use null if output
	 * must not be encrypted.
	 * @param encryptionPassword encryption password to be used.
	 * @throws IOException if the data can not be written 
	 * @throws IllegalArgumentException if encryptionAlg is unsupported
	 */
	public static void savePrivateKey(OutputStream os, PrivateKey pk, 
			Encoding format, String encryptionAlg, char[] encryptionPassword) 
			throws IOException, IllegalArgumentException
	{
		PKCS8Generator gen;
		if (encryptionAlg != null)
		{
			try
			{
				gen = new PKCS8Generator(pk, encryptionAlg, "BC");
				gen.setPassword(encryptionPassword);
			} catch (NoSuchProviderException e)
			{
				throw new RuntimeException("UPS! Default provider is not known!", e);
			} catch (NoSuchAlgorithmException e)
			{
				throw new IllegalArgumentException("Unknown encryption algorithm " 
						+ encryptionAlg, e);
			}
		} else
			gen = new PKCS8Generator(pk);
		
		if (format.equals(Encoding.PEM))
		{
			PemWriter writer = new PemWriter(new OutputStreamWriter(os, ASCII));
			writer.writeObject(gen);
			writer.flush();
		} else
		{
			if (encryptionAlg == null)
			{
				os.write(pk.getEncoded());
			} else
			{
				PemObject pemO = gen.generate();
				os.write(pemO.getContent());
			}
			os.flush();
		}
	}
	
	/**
	 * Saves the provided certificate chain to the output file, using the requested 
	 * encoding.
	 * @param os where to write the encoded certificate to 
	 * @param chain certificate chain to save
	 * @param format format to use
	 * @throws IOException if the data can not be written
	 */
	public static void saveCertificateChain(OutputStream os, X509Certificate[] chain, 
			Encoding format) throws IOException
	{
		byte [][] der = new byte[chain.length][];
		int total = 0;
		for (int i=0; i<chain.length; i++)
		{
			try
			{
				der[i] = chain[i].getEncoded();
			} catch (CertificateEncodingException e)
			{
				throw new IOException("Can't encode the certificate into ASN1 DER format", e);
			}
			total += der[i].length;
		}
		
		if (format.equals(Encoding.PEM))
		{
			final byte []finalBuf = new byte[total];
			for (int i=0, pos=0; i<der.length; i++)
			{
				System.arraycopy(der[i], 0, finalBuf, pos, der[i].length);
				pos+=der[i].length;
			}
			PemWriter pemWriter = new PemWriter(new OutputStreamWriter(os, ASCII));
			pemWriter.writeObject(new PemObjectGenerator(){
				public PemObject generate()
						throws PemGenerationException
				{
					return new PemObject("CERTIFICATE", finalBuf);
				}
			});
			pemWriter.flush();
		} else
		{
			for (int i=0; i<der.length; i++)
				os.write(der[i]);
			os.flush();
		}
	}
	
	/**
	 * Saves the chosen private key entry from the provided keystore as a plain 
	 * text PEM data. The produced PEM contains the private key first and then all
	 * certificates which are stored in the provided keystore under the given alias.
	 * The order from the keystore is preserved.  
	 *  
	 * @param os  where to write the encoded data to
	 * @param ks keystore to read from
	 * @param alias alias of the private key entry in the keystore
	 * @param keyPassword password of the private key in the keystore
	 * @param encryptionAlg encryption algorithm to be used.
	 * See {@link PKCS8Generator} constants for available names. Use null if output
	 * must not be encrypted.
	 * @param encryptionPassword encryption password to be used.
	 * @throws IOException if the data can not be written
	 * @throws KeyStoreException if the provided alias does not exist in the keystore 
	 * or if it does not correspond to the private key entry.
	 * @throws IllegalArgumentException if encriptionAlg is unsupported or alias is wrong
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 */
	public static void savePEMKeystore(OutputStream os, KeyStore ks, String alias,
			String encryptionAlg, char[] keyPassword, char[] encryptionPassword) 
		throws IOException, KeyStoreException, IllegalArgumentException, UnrecoverableKeyException, NoSuchAlgorithmException
	{
		Key k = ks.getKey(alias, keyPassword);
		if (k == null)
			throw new IllegalArgumentException("The specified alias does not correspond to any key entry");
		if (!(k instanceof PrivateKey))
			throw new IllegalArgumentException("The alias corresponds to a secret key, not to the private key");

		savePrivateKey(os, (PrivateKey)k, Encoding.PEM, encryptionAlg, encryptionPassword);
		X509Certificate[] certs = convertToX509Chain(ks.getCertificateChain(alias));
		saveCertificateChain(os, certs, Encoding.PEM);
	}
}
