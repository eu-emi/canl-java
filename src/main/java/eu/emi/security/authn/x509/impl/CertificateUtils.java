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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.crypto.BadPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.CachedPEMReader;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.CertificateHelpers.PEMContentsType;
import eu.emi.security.authn.x509.helpers.CharArrayPasswordFinder;
import eu.emi.security.authn.x509.helpers.FlexiblePEMReader;
import eu.emi.security.authn.x509.helpers.KeyStoreHelper;
import eu.emi.security.authn.x509.helpers.PKCS8DERReader;
import eu.emi.security.authn.x509.helpers.PasswordSupplier;

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
	
	/**
	 * Configures security providers which are used by the library. Can be called 
	 * multiple times (subsequent calls won't have any effect). 
	 * <p>
	 * This method must be called before any other usage of the code from canl API. 
	 */
	public static void configureSecProvider()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
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
	 * Loads a single certificate from the provided input stream. The stream is always closed afterwards.
	 * @param is input stream to read encoded certificate from
	 * @param format encoding type
	 * @return loaded certificate
	 * @throws IOException if certificate can not be read or parsed
	 */
	public static X509Certificate loadCertificate(InputStream is, Encoding format) 
			throws IOException
	{
		InputStream realIS = is;
		if (format.equals(Encoding.PEM))
		{
			ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
			Reader br = new InputStreamReader(is, ASCII);
			FlexiblePEMReader pemReader = new FlexiblePEMReader(br);
			try
			{
				PemObject pem = pemReader.readPemObject();
				if (pem == null)
					throw new IOException("PEM data not found in the stream and its end was reached");
				PEMContentsType type = CertificateHelpers.getPEMType(pem.getType());
				if (!type.equals(PEMContentsType.CERTIFICATE))
					throw new IOException("Expected PEM encoded certificate but found: " + type);
				buffer.write(pem.getContent());

				realIS = new ByteArrayInputStream(buffer.toByteArray());
			} finally
			{
				pemReader.close();
			}
		}
		Certificate cert = CertificateHelpers.readDERCertificate(realIS);
		
		if (!(cert instanceof X509Certificate))
			throw new IOException("The DER input contains a certificate which is not a " +
					"X.509Certificate, it is " + cert.getClass().getName());
		return (X509Certificate)cert;
	}

	/**
	 * Loads a private key from the provided input stream. The input stream must be encoded
	 * in the PKCS8 format (PEM or DER). Additionally in case of PEM encoding the legacy 
	 * OpenSSL format for storing private keys is supported. Such PEM header names
	 * has algorithm {RSA|DSA|EC} placed before the PRIVATE KEY string.
	 * <p>
	 * Currently supported key encryption algorithms are DES and 3 DES. RC2 is unsupported.
	 * <p>
	 * NOTE: currently it is unsupported to load DER private keys which were encoded with openssl 
	 * legacy encoding (e.g. with @verbatim openssl rsa -outform der ... @endverbatim). PEM files
	 * in openssl legacy encoding are supported. 
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
			return loadPEMPrivateKey(is, getPF(password));
		} else
			return loadDERPrivateKey(is, password);
	}

	/**
	 * Loads a private key from the provided input stream. The input stream must be encoded
	 * in the PEM format. This method is a special purpose version of the 
	 * {@link #loadPrivateKey(InputStream, Encoding, char[])}. It allows to provide {@link PasswordSupplier}
	 * instead of the actual password. The {@link PasswordSupplier} implementation will be used only if
	 * the source is encrypted.
	 * <p>
	 * All other limitations and features are as in the {@link #loadPrivateKey(InputStream, Encoding, char[])}
	 * method.  
	 * @param is input stream to read encoded key from
	 * @param pf password finder used to discover key's encryption password. 
	 * It is used only if the password is actually needed.
	 * @return loaded key
	 * @throws IOException if key can not be read or parsed
	 */
	public static PrivateKey loadPEMPrivateKey(InputStream is, PasswordSupplier pf) throws IOException
	{
		Reader reader = new InputStreamReader(is, Charset.forName("US-ASCII"));
		FlexiblePEMReader pemReader = new FlexiblePEMReader(reader);
		return internalLoadPK(pemReader, "PEM", pf);
	}

	private static PrivateKey parsePEMPrivateKey(PemObject pem, PasswordSupplier pf) 
			throws IOException
	{
		CachedPEMReader pemReader = new CachedPEMReader(pem);
		return internalLoadPK(pemReader, "PEM", pf);
	}

	private static PrivateKey internalLoadPK(PEMParser pemReader, String type, PasswordSupplier pf) 
			throws IOException
	{
		Object ret = null;
		try
		{
			ret = pemReader.readObject();
			if (ret == null)
				throw new IOException("Can not load the " + type + 
						" private key: no input data (empty source?)");
		} catch (IOException e)
		{
			if (e.getCause() != null && e.getCause() instanceof BadPaddingException)
			{
				throw new IOException("Can not load " + type + " private key: the password is " +
						"incorrect or the " + type + " data is corrupted.", e);
			}
			throw new IOException("Can not load the " + type + " private key: " + e);
		}
		return convertToPrivateKey(ret, type, pf);
	}

	
	private static PrivateKey convertToPrivateKey(Object pemObject, String type, PasswordSupplier pf) throws IOException
	{
		PrivateKeyInfo pki;
		try
		{
			pki = resolvePK(type, pemObject, pf);
		} catch (OperatorCreationException e)
		{
			throw new IOException("Can't initialize decryption infrastructure", e);
		} catch (PKCSException e)
		{
			throw new IOException("Error decrypting private key: the password is " +
						"incorrect or the " + type + " data is corrupted.", e);
		}
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		return converter.getPrivateKey(pki);
	}
	
	private static PrivateKeyInfo resolvePK(String type, Object src, PasswordSupplier pf) throws 
		IOException, OperatorCreationException, PKCSException
	{
		if (src instanceof PrivateKeyInfo)
			return (PrivateKeyInfo) src;
		
		if (src instanceof PEMKeyPair)
			return ((PEMKeyPair)src).getPrivateKeyInfo();
		
		if (pf == null)
			throw new MissingPasswordForEncryptedKeyException();
		
		if (src instanceof PKCS8EncryptedPrivateKeyInfo)
		{
			JceOpenSSLPKCS8DecryptorProviderBuilder provBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
			InputDecryptorProvider decProvider = provBuilder.build(pf.getPassword());
			return ((PKCS8EncryptedPrivateKeyInfo)src).decryptPrivateKeyInfo(decProvider);
		}
		
		if (src instanceof PEMEncryptedKeyPair)
		{
			JcePEMDecryptorProviderBuilder provBuilder = new JcePEMDecryptorProviderBuilder();
			PEMDecryptorProvider decProvider = provBuilder.build(pf.getPassword());
			PEMKeyPair keyPair = ((PEMEncryptedKeyPair)src).decryptKeyPair(decProvider);
			return keyPair.getPrivateKeyInfo();
		}
		
		throw new IOException("The " + type + " input does not contain a private key, " +
				"it was parsed as " + src.getClass().getName());
	}

	
	private static PrivateKey loadDERPrivateKey(InputStream is, char[] password) 
			throws IOException
	{
		String type = "DER";
		Object ret = null;
		PKCS8DERReader derReader = new PKCS8DERReader(is, password != null);
		try
		{
			ret = derReader.readObject();
			derReader.close();
			if (ret == null)
				throw new IOException("Can not load the " + type + 
						" private key: no input data (empty source?)");
		} catch (IOException e)
		{
			if (e.getCause() != null && e.getCause() instanceof BadPaddingException)
			{
				throw new IOException("Can not load " + type + " private key: the password is " +
						"incorrect or the " + type + " data is corrupted.", e);
			}
			throw new IOException("Can not load the " + type + " private key: ", e);
		}
		
		return convertToPrivateKey(ret, type, getPF(password));
	}

	/**
	 * Loads a set of (possibly unrelated to each other) certificates from the provided input stream. 
	 * The input stream is always closed afterwards.
	 * 
	 * @param is input stream to read encoded certificates from
	 * @param format encoding type
	 * @return loaded certificates array
	 * @throws IOException if certificates can not be read or parsed
	 */
	public static X509Certificate[] loadCertificates(InputStream is, Encoding format) throws IOException
	{
		InputStream realIS = is;
		if (format.equals(Encoding.PEM))
		{
			boolean readOne = false;
			ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
			Reader br = new InputStreamReader(is, ASCII);
			FlexiblePEMReader pemReader = new FlexiblePEMReader(br);
			try
			{
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
			} finally
			{
				pemReader.close();
			}
			realIS = new ByteArrayInputStream(buffer.toByteArray());
		}
		return loadDERCertificates(realIS);
	}
	
	/**
	 * Loads a chain of certificates from the provided input stream. The input stream is always closed afterwards.
	 * @param is input stream to read encoded certificates from
	 * @param format encoding type
	 * @return loaded certificates array
	 * @throws IOException if certificates can not be read or parsed
	 */
	public static X509Certificate[] loadCertificateChain(InputStream is, Encoding format) throws IOException
	{
		X509Certificate[] unsorted = loadCertificates(is, format);
		List<X509Certificate> unsortedList = new ArrayList<X509Certificate>();
		Collections.addAll(unsortedList, unsorted);
		return CertificateHelpers.sortChain(unsortedList);
	}

	private static X509Certificate[] loadDERCertificates(InputStream is) throws IOException
	{
		Collection<? extends Certificate> certs = CertificateHelpers.readDERCertificates(is);
		Iterator<? extends Certificate> iterator = certs.iterator();
		X509Certificate []ret = new X509Certificate[certs.size()];
		for (int i=0; i<ret.length; i++)
		{
			Certificate c = iterator.next();
			if (!(c instanceof X509Certificate))
				throw new IOException("The DER input contains a certificate which is not a " +
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
		return loadPEMKeystore(is, getPF(password), ksPassword);
	}
	
	/**
	 * As {@link #loadPEMKeystore(InputStream, char[], char[])} but this version allows for providing input
	 * key's encryption password only when needed. Input stream is always closed afterwards.
	 *  
	 * @param is input stream to read from
	 * @param pf implementation will be used to get the password needed to decrypt the private key 
	 * from the PEM keystore. Won't be used if the key happens to be unencrypted.
	 * @param ksPassword password which is used to encrypt the private key in the keystore. 
	 * Can not be null.
	 * @return KeyStore with one private key typed entry, with alias 
	 * {@link #DEFAULT_KEYSTORE_ALIAS} of the JKS type. If password is != null then it is also
	 * used to crypt the key in the keystore. If it is null then #
	 * @throws IOException if input can not be read or parsed
	 */
	public static KeyStore loadPEMKeystore(InputStream is, PasswordSupplier pf, char[] ksPassword) throws IOException
	{
		PrivateKey pk = null;
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		Reader br = new InputStreamReader(is, ASCII);
		FlexiblePEMReader pemReader = new FlexiblePEMReader(br);
		try
		{
			do
			{
				PemObject pem = pemReader.readPemObject();
				if (pem == null)
					break;
				PEMContentsType type = CertificateHelpers.getPEMType(pem.getType());
				if (type.equals(PEMContentsType.PRIVATE_KEY) || 
						type.equals(PEMContentsType.LEGACY_OPENSSL_PRIVATE_KEY))
				{
					if (pk != null)
						throw new IOException("Multiple private keys were found");
					pk = parsePEMPrivateKey(pem, pf);
				} else if (type.equals(PEMContentsType.CERTIFICATE))
				{
					X509Certificate[] certs = loadDERCertificates(
							new ByteArrayInputStream(pem.getContent()));
					for (X509Certificate cert: certs)
						certChain.add(cert);
				} else
				{
					throw new IOException("Unsupported PEM object found in the input: " + type);
				}
			} while (true);
		} finally
		{
			pemReader.close();
		}
		
		if (pk == null)
		{
			throw new IOException("Private key was not found in the PEM keystore (" + 
					certChain.size() + " certificate(s) was (were) found).");
		}
		
		Certificate []chain = CertificateHelpers.sortChain(certChain);
		
		KeyStore ks;
		try
		{
			ks = KeyStoreHelper.getInstanceForCredential("JKS");
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
	 * <b> WARNING </b> The output stream IS NOT closed afterwards. This is on purpose,
	 * so it is possible to write additional output.
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
			@SuppressWarnings("resource")
			JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(os, ASCII));
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
	 * As {@link #savePrivateKey(OutputStream, PrivateKey, Encoding, String, char[], boolean)} with
	 * the last argument equal to false 
	 * 
	 * @param os where to write the encoded key to 
	 * @param pk key to save
	 * @param format format to use
	 * @param encryptionAlg encryption algorithm to be used. 
	 * See {@link #savePrivateKey(OutputStream, PrivateKey, Encoding, String, char[], boolean)} documentation
	 * for details about allowed values.
	 * @param encryptionPassword encryption password to be used.
	 * @throws IOException if the data can not be written 
	 * @throws IllegalArgumentException if encryptionAlg is unsupported
	 */
	public static void savePrivateKey(OutputStream os, PrivateKey pk, 
			Encoding format, String encryptionAlg, char[] encryptionPassword) 
			throws IOException, IllegalArgumentException
	{
		savePrivateKey(os, pk, format, encryptionAlg, encryptionPassword, false);
	}
	
	/**
	 * Saves the provided private key to the output file, using the requested encoding.
	 * Allows for using PKCS #8 or the legacy openssl PKCS #1 encoding.
	 * <b> WARNING </b> The output stream IS NOT closed afterwards. This is on purpose,
	 * so it is possible to write additional output.
	 * 
	 * @param os where to write the encoded key to 
	 * @param pk key to save
	 * @param format format to use
	 * @param encryptionAlg encryption algorithm to be used. 
	 * Use null if output must not be encrypted.
	 * For PKCS8 output see {@link JceOpenSSLPKCS8EncryptorBuilder} constants for available names. 
	 * For the legacy openssl format, one can use the 
	 * algorithm names composed from 3 parts glued with hyphen. The first part determines algorithm,
	 * one of AES, DES, BF and RC2. The second part determines key bits and is used for AES and
	 * optionally for RC2. For AES it is possible to use values
	 * 128, 192 and 256. For RC2 64, 40 can be used or nothing - then value 128 is used.
	 * The last part determines the block mode: CFB, ECB, OFB, EDE and CBC. Additionally EDE3 
	 * can be used in combination with DES to use DES3 with EDE. Examples:
	 * AES-192-ECB or DES-EDE3.  
	 * @param encryptionPassword encryption password to be used.
	 * @param opensslLegacyFormat if true the key is saved in the legacy openssl format. Otherwise a 
	 * PKCS #8 is used.
	 * @throws IOException if the data can not be written 
	 * @throws IllegalArgumentException if encryptionAlg is unsupported
	 * @since 1.1.0
	 */
	public static void savePrivateKey(OutputStream os, PrivateKey pk, 
			Encoding format, String encryptionAlg, char[] encryptionPassword, 
			boolean opensslLegacyFormat) 
			throws IOException, IllegalArgumentException
	{
		PemObjectGenerator gen;
		if (encryptionAlg != null)
		{
			try
			{
				if (!opensslLegacyFormat)
				{
					JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = 
							new JceOpenSSLPKCS8EncryptorBuilder(
									new ASN1ObjectIdentifier(encryptionAlg));
				        encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
				        encryptorBuilder.setPassword(encryptionPassword);
				        
					OutputEncryptor oe = encryptorBuilder.build();
					gen = new JcaPKCS8Generator(pk, oe);
				} else
				{
					JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder(encryptionAlg);
					builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
					builder.setSecureRandom(new SecureRandom());
					PEMEncryptor encryptor = builder.build(encryptionPassword);
					gen = new JcaMiscPEMGenerator(pk, encryptor);
				}
			} catch (OperatorCreationException e)
			{
				throw new IllegalArgumentException("Can't setup encryption modules, " +
						"likely the parameters (as algorithm) are invalid", e);
			}
		} else
		{
			if (!opensslLegacyFormat)
				gen = new JcaPKCS8Generator(pk, null);
			else
			{
				gen = new JcaMiscPEMGenerator(pk);
			}
		}
		
		if (format.equals(Encoding.PEM))
		{
			@SuppressWarnings("resource")
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
	 * Saves the provided certificate chain to the output stream, using the requested 
	 * encoding.
 	 * <b> WARNING </b> The output stream IS NOT closed afterwards. This is on purpose,
	 * so it is possible to write additional output.
	 * @param os where to write the encoded certificate to 
	 * @param chain certificate chain to save
	 * @param format format to use
	 * @throws IOException if the data can not be written
	 */
	public static void saveCertificateChain(OutputStream os, X509Certificate[] chain, 
			Encoding format) throws IOException
	{
		if (format.equals(Encoding.PEM))
		{
			for (X509Certificate cert: chain)
				saveCertificate(os, cert, Encoding.PEM);
		} else
		{
			byte [][] der = new byte[chain.length][];
			for (int i=0; i<chain.length; i++)
			{
				try
				{
					der[i] = chain[i].getEncoded();
				} catch (CertificateEncodingException e)
				{
					throw new IOException("Can't encode the certificate into ASN1 DER format", e);
				}
			}
			
			for (int i=0; i<der.length; i++)
				os.write(der[i]);
			os.flush();
		}
	}
	
	/**
	 * See {@link #savePEMKeystore(OutputStream, KeyStore, String, String, char[], char[], boolean)}
	 * with the last argument equal to false.
	 *  
	 * @param os where to write the encoded data to
	 * @param ks keystore to read from
	 * @param alias alias of the private key entry in the keystore
	 * @param encryptionAlg encryption algorithm to be used.
	 * See {@link #savePrivateKey(OutputStream, PrivateKey, Encoding, String, char[], boolean)} documentation
	 * for details about allowed values.
	 * @param keyPassword password of the private key in the keystore
	 * @param encryptionPassword encryption password to be used.
	 * @throws IOException if the data can not be written
	 * @throws KeyStoreException if the provided alias does not exist in the keystore 
	 * or if it does not correspond to the private key entry.
	 * @throws IllegalArgumentException if encriptionAlg is unsupported or alias is wrong
	 * @throws NoSuchAlgorithmException if algorithm is not known
	 * @throws UnrecoverableKeyException if key can not be recovered
	 */
	public static void savePEMKeystore(OutputStream os, KeyStore ks, String alias,
			String encryptionAlg, char[] keyPassword, char[] encryptionPassword) 
		throws IOException, KeyStoreException, IllegalArgumentException, UnrecoverableKeyException, NoSuchAlgorithmException
	{
		savePEMKeystore(os, ks, alias, encryptionAlg, keyPassword, encryptionPassword, false);
	}

	/**
	 * See {@link #savePEMKeystore(OutputStream, KeyStore, String, String, char[], char[], boolean)}.
	 * This method allows for using the CANL {@link X509Credential} instead of low level
	 * {@link KeyStore} as argument.
	 *  
	 * @param os where to write the encoded data to
	 * @param toSave CANL X509Credential to read from
	 * @param encryptionAlg encryption algorithm to be used.
	 * See {@link #savePrivateKey(OutputStream, PrivateKey, Encoding, String, char[], boolean)} documentation
	 * for details about allowed values.
	 * @param encryptionPassword encryption password to be used.
	 * @param opensslLegacyFormat if true the key is saved in the legacy openssl format. Otherwise a 
	 * PKCS #8 is used.
	 * @throws IOException if the data can not be written
	 * @throws KeyStoreException if the provided alias does not exist in the keystore 
	 * or if it does not correspond to the private key entry.
	 * @throws IllegalArgumentException if encriptionAlg is unsupported or alias is wrong
	 * @throws NoSuchAlgorithmException if algorithm is not known
	 * @throws UnrecoverableKeyException if key can not be recovered
	 */
	public static void savePEMKeystore(OutputStream os, X509Credential toSave,
			String encryptionAlg, char[] encryptionPassword, boolean opensslLegacyFormat) 
		throws IOException, KeyStoreException, IllegalArgumentException, UnrecoverableKeyException, NoSuchAlgorithmException
	{
		savePEMKeystore(os, toSave.getKeyStore(), toSave.getKeyAlias(), 
				encryptionAlg, toSave.getKeyPassword(), 
				encryptionPassword, opensslLegacyFormat);
	}
	
	/**
	 * Saves the chosen private key entry from the provided keystore as a plain 
	 * text PEM data. The produced PEM contains the private key first and then all
	 * certificates which are stored in the provided keystore under the given alias.
	 * The order from the keystore is preserved. The output stream is closed afterwards 
	 * only if the write operation was successful (there was no exception).  
	 *  
	 * @param os where to write the encoded data to
	 * @param ks keystore to read from
	 * @param alias alias of the private key entry in the keystore
	 * @param encryptionAlg encryption algorithm to be used.
	 * See {@link #savePrivateKey(OutputStream, PrivateKey, Encoding, String, char[], boolean)} documentation
	 * for details about allowed values.
	 * @param keyPassword password of the private key in the keystore
	 * @param encryptionPassword encryption password to be used.
	 * @param opensslLegacyFormat if true the key is saved in the legacy openssl format. Otherwise a 
	 * PKCS #8 is used.
	 * @throws IOException if the data can not be written
	 * @throws KeyStoreException if the provided alias does not exist in the keystore 
	 * or if it does not correspond to the private key entry.
	 * @throws IllegalArgumentException if encriptionAlg is unsupported or alias is wrong
	 * @throws NoSuchAlgorithmException if algorithm is not known
	 * @throws UnrecoverableKeyException if key can not be recovered
	 */
	public static void savePEMKeystore(OutputStream os, KeyStore ks, String alias,
			String encryptionAlg, char[] keyPassword, char[] encryptionPassword, boolean opensslLegacyFormat) 
		throws IOException, KeyStoreException, IllegalArgumentException, UnrecoverableKeyException, NoSuchAlgorithmException
	{
		Key k = ks.getKey(alias, keyPassword);
		if (k == null)
			throw new IllegalArgumentException("The specified alias does not correspond to any key entry");
		if (!(k instanceof PrivateKey))
			throw new IllegalArgumentException("The alias corresponds to a secret key, not to the private key");

		savePrivateKey(os, (PrivateKey)k, Encoding.PEM, encryptionAlg, encryptionPassword, opensslLegacyFormat);
		X509Certificate[] certs = convertToX509Chain(ks.getCertificateChain(alias));
		saveCertificateChain(os, certs, Encoding.PEM);
		os.close();
	}
	
	
	public static PasswordSupplier getPF(char[] password)
	{
		return (password == null) ? null : new CharArrayPasswordFinder(password);
	}
	
	
	public static class MissingPasswordForEncryptedKeyException extends IOException
	{
		public MissingPasswordForEncryptedKeyException()
		{
			super("The key is password protected and the password was not provided");
		}
	}
}
