/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.proxy.BaseProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.CertificateExtension;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyPolicy;
import eu.emi.security.authn.x509.proxy.ProxyRequestOptions;
import eu.emi.security.authn.x509.proxy.ProxyType;

/**
 * Actual implementation of the Proxy generation. The object is for one use only, 
 * i.e. it should not be reused to generate first certificate. It is strongly suggested
 * to use {@link ProxyGenerator}.
 * 
 * @author K. Benedyczak
 */
public class ProxyGeneratorHelper
{
	private SubjectPublicKeyInfo proxyPublicKeyInfo = null;
	private transient PrivateKey proxyPrivateKey = null;
	private X509v3CertificateBuilder certBuilder;
	private X509Certificate proxy;
	
	/**
	 * Generate the proxy certificate object from the local certificate.
	 * 
	 * @param param proxy parameters
	 * @param privateKey key to sign the proxy
	 * @return a newly created proxy certificate, wrapped together with a private key 
	 * if it was also generated.
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException 
	 * @throws CertificateEncodingException
	 */
	public ProxyCertificate generate(ProxyCertificateOptions param,
			PrivateKey privateKey) throws InvalidKeyException,
			SignatureException, NoSuchAlgorithmException,
			CertificateParsingException, IOException
	{
		establishKeys(param);
		return generateCommon(param, privateKey);
	}

	
	/**
	 * Generate the proxy certificate object from the received Certificate Signing Request.
	 *  
	 * @param param proxy parameters
	 * @param privateKey key to sign the proxy
	 * @return chain with the new proxy on the first position
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 */
	public X509Certificate[] generate(ProxyRequestOptions param,
			PrivateKey privateKey) throws InvalidKeyException,
			SignatureException, NoSuchAlgorithmException,
			CertificateParsingException, IOException
	{
		PKCS10CertificationRequest csr = param.getProxyRequest();
		proxyPublicKeyInfo = csr.getSubjectPublicKeyInfo();
		return generateCommon(param, privateKey).getCertificateChain();
	}

	private ProxyCertificate generateCommon(BaseProxyCertificateOptions param,
			PrivateKey privateKey) throws InvalidKeyException,
			SignatureException, NoSuchAlgorithmException,
			CertificateParsingException, IOException
	{
		setupCertBuilder(param);
		addExtensions(param);
		
		try
		{
			buildCertificate(param.getParentCertChain()[0], privateKey);
		} catch (NoSuchProviderException e)
		{
			throw new RuntimeException("Default signature provider " +
					"is not available? A bug or serious JDK misconfiguration.", e);
		} catch (IOException e)
		{
			throw new CertificateParsingException("Can not encode the certificate " +
					"to the binary DER form", e);
		}
		return wrapResult(param.getParentCertChain());
	}
	
	
	private void establishKeys(ProxyCertificateOptions param) throws InvalidKeyException
	{
		PublicKey proxyPublicKey = param.getPublicKey(); 
		proxyPrivateKey = null;
		if (proxyPublicKey == null)
		{
			KeyPair pair = ProxyGeneratorHelper.generateKeyPair(param.getKeyLength());
			proxyPublicKey = pair.getPublic();
			proxyPrivateKey = pair.getPrivate();
		}

                ASN1InputStream is = null;
		try
		{
                        is = new ASN1InputStream(proxyPublicKey.getEncoded());
			proxyPublicKeyInfo = SubjectPublicKeyInfo.getInstance(is.readObject());
		} catch (IOException e)
		{
			throw new InvalidKeyException("Can not parse the public key" +
					"being included in the proxy certificate", e);
		} finally {
                    if (is != null) {
                        try {
                            is.close();
                        } catch (IOException consumed) {
                        }
                    }
                }
	}

	private void setupCertBuilder(BaseProxyCertificateOptions param) throws InvalidKeyException
	{
		X509Certificate issuingCert = param.getParentCertChain()[0];
		
		Date notBefore = param.getNotBefore();
		Date notAfter = new Date(notBefore.getTime() + param.getLifetime()*1000L);
		BigInteger serial = establishSerial(param);
		X500Name issuer = CertificateHelpers.toX500Name(issuingCert.getSubjectX500Principal()); 
		X500Name subject = ProxyGeneratorHelper.generateDN(issuingCert.getSubjectX500Principal(), 
				param.getType(), param.isLimited(), serial);
		
		certBuilder = new X509v3CertificateBuilder(
				issuer,
				serial, 
				notBefore, 
				notAfter, 
				subject, 
				proxyPublicKeyInfo);
	}
	
	/**
	 * If the input chain has no KeyUsage extension null is returned. If at least one certificate in the chain
	 * has the Key Usage extension then a KeyUsage is returned which contains bitwise AND of KeyUsage flags 
	 * from all certificates.
	 * @param chain
	 * @return
	 */
	public static Integer getChainKeyUsage(X509Certificate[] chain)
	{
		int flags = 0xFF | KeyUsage.decipherOnly;
		boolean found = false;
		for (X509Certificate cert: chain)
		{
			boolean[] certKu = cert.getKeyUsage();
			if (certKu == null)
				continue;
			found = true;
			int certKuInt = 0;
			for (int i=0; i<certKu.length; i++)
			{
				if (!certKu[i])
					continue;
				int bit = (i == 8) ? KeyUsage.decipherOnly : (1 << (7-i));
				certKuInt |= bit;
			}
			flags &= certKuInt;
		}
		return found ? flags : null; 
	}
	
	
	private KeyUsage establishKeyUsage(BaseProxyCertificateOptions param)
	{
		Integer parentKU = getChainKeyUsage(param.getParentCertChain());
		int retMask;
		if (parentKU == null)
		{
			retMask = param.getProxyKeyUsageMask() < 0 ? BaseProxyCertificateOptions.DEFAULT_KEY_USAGE :
				param.getProxyKeyUsageMask();
		} else
		{
			retMask = param.getProxyKeyUsageMask() < 0 ? parentKU : 
				param.getProxyKeyUsageMask() & parentKU;			
		}
		
		return new KeyUsage(retMask);
	}
	
	private void addExtensions(BaseProxyCertificateOptions param) throws IOException
	{
		KeyUsage ks = establishKeyUsage(param);
		certBuilder.addExtension(X509Extension.keyUsage, true, ks);
		
		if (param.getType() != ProxyType.LEGACY)
		{
			ProxyPolicy policy = param.getPolicy();
			if (policy == null)
				policy = new ProxyPolicy(ProxyPolicy.INHERITALL_POLICY_OID);
			
			String oid = param.getType() == ProxyType.DRAFT_RFC ? ProxyCertInfoExtension.DRAFT_EXTENSION_OID 
					: ProxyCertInfoExtension.RFC_EXTENSION_OID;
			ProxyCertInfoExtension extValue = new ProxyCertInfoExtension(param.getProxyPathLimit(), policy);
			certBuilder.addExtension(new ASN1ObjectIdentifier(oid), 
					true, extValue);
		}
		
		if (param.getProxyTracingIssuer() != null)
		{
			ProxyTracingExtension extValue = new ProxyTracingExtension(param.getProxyTracingIssuer());
			certBuilder.addExtension(new ASN1ObjectIdentifier(ProxyTracingExtension.PROXY_TRACING_ISSUER_EXTENSION_OID), 
					false, extValue);
		}
		if (param.getProxyTracingSubject() != null)
		{
			ProxyTracingExtension extValue = new ProxyTracingExtension(param.getProxyTracingSubject());
			certBuilder.addExtension(new ASN1ObjectIdentifier(ProxyTracingExtension.PROXY_TRACING_SUBJECT_EXTENSION_OID), 
					false, extValue);
		}
		
		if (param.getSAMLAssertion() != null)
		{
			ProxySAMLExtension extValue = new ProxySAMLExtension(param.getSAMLAssertion());
			certBuilder.addExtension(new ASN1ObjectIdentifier(ProxySAMLExtension.SAML_OID), 
					false, extValue);
		}
		
		if (param.getAttributeCertificates() != null)
		{
			ProxyACExtension extValue = new ProxyACExtension(param.getAttributeCertificates());
			certBuilder.addExtension(new ASN1ObjectIdentifier(ProxyACExtension.AC_OID), 
					false, extValue);
		}
		
		String[] srcExcl = param.getSourceRestrictionExcludedAddresses();
		String[] srcPerm = param.getSourceRestrictionPermittedAddresses();
		if (srcExcl != null || srcPerm != null)
		{
			ProxyAddressRestrictionData extValue = new ProxyAddressRestrictionData();
			if (srcExcl != null)
			{
				for (String addr: srcExcl)
					extValue.addExcludedIPAddressWithNetmask(addr);
			}
			if (srcPerm != null)
			{
				for (String addr: srcPerm)
					extValue.addPermittedIPAddressWithNetmask(addr);
			}
			certBuilder.addExtension(new ASN1ObjectIdentifier(ProxyAddressRestrictionData.SOURCE_RESTRICTION_OID), 
					false, extValue);
		}

		String[] tgtExcl = param.getTargetRestrictionExcludedAddresses();
		String[] tgtPerm = param.getTargetRestrictionPermittedAddresses();
		if (tgtExcl != null || tgtPerm != null)
		{
			ProxyAddressRestrictionData extValue = new ProxyAddressRestrictionData();
			if (tgtExcl != null)
			{
				for (String addr: tgtExcl)
					extValue.addExcludedIPAddressWithNetmask(addr);
			}
			if (tgtPerm != null)
			{
				for (String addr: tgtPerm)
					extValue.addPermittedIPAddressWithNetmask(addr);
			}
			certBuilder.addExtension(new ASN1ObjectIdentifier(ProxyAddressRestrictionData.TARGET_RESTRICTION_OID), 
					false, extValue);
		}
		
		List<CertificateExtension> additionalExts = param.getExtensions();
		for (CertificateExtension ext: additionalExts)
			certBuilder.addExtension(new ASN1ObjectIdentifier(ext.getOid()), 
					ext.isCritical(), ext.getValue());
	}
	
	private void buildCertificate(X509Certificate issuingCert, PrivateKey privateKey) 
			throws CertificateParsingException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, IOException
	{
		AlgorithmIdentifier sigAlg;
		try
		{
			sigAlg = X509v3CertificateBuilder.extractAlgorithmId(
					issuingCert);
		} catch (IOException e)
		{
			throw new CertificateParsingException("Can not parse parameters of the " +
					"public key contained in the issuer certificate", e);
		}
		String sigAlgName = issuingCert.getSigAlgName();
		proxy = certBuilder.build(privateKey, 
				sigAlg, 
				sigAlgName, 
				null, 
				null);
	}
	
	private ProxyCertificate wrapResult(X509Certificate []originalChain) 
			throws InvalidKeyException
	{
		X509Certificate []extendedChain = new X509Certificate[originalChain.length + 1];
		
		for (int i=0; i<originalChain.length; i++)
			extendedChain[i+1] = originalChain[i];
		extendedChain[0] = proxy;
		
		if (proxyPrivateKey != null)
		{
			try
			{
				return new ProxyCertificateImpl(extendedChain, proxyPrivateKey);
			} catch (KeyStoreException e)
			{
				throw new InvalidKeyException("The generated private key is unsupported, bug?", e);
			}
		} else
			return new ProxyCertificateImpl(extendedChain);
	}
	
	/**
	 * For LEGACY proxies returns the serial from the issuing certificate. 
	 * For the Drfat/rfc proxies returns the manually set serial, or generateas a
	 * random one if not set.
	 * @param param
	 * @return serial number
	 */
	public static BigInteger establishSerial(BaseProxyCertificateOptions param)
	{
		if (param.getType() == ProxyType.LEGACY)
			return param.getParentCertChain()[0].getSerialNumber();
		if (param.getSerialNumber() != null)
			return param.getSerialNumber();
		SecureRandom rand = new SecureRandom();
		return BigInteger.valueOf(rand.nextInt()).abs();
	}
	

	/**
	 * Generate a correct DN for the proxy, depending on its type.
	 * @param parentSubject
	 * @param type
	 * @param limited
	 * @param serial
	 * @return generated proxy DN
	 */
	public static X500Name generateDN(X500Principal parentSubject, ProxyType type, boolean limited, 
			BigInteger serial)
	{
		String cn;
		if (type == ProxyType.LEGACY)
			cn = limited ? "limited proxy" : "proxy";
		else
			cn = serial.toString();
		
		X500Name dn = CertificateHelpers.toX500Name(parentSubject);
		AttributeTypeAndValue ava = new AttributeTypeAndValue(BCStyle.CN, new DERPrintableString(cn));
		RDN added = new RDN(ava);
		RDN []orig = dn.getRDNs();
		RDN []proxyRDNs = new RDN[orig.length + 1];
		for (int i=0; i<orig.length; i++)
			proxyRDNs[i] = orig[i];
		proxyRDNs[orig.length] = added;
		return new X500Name(proxyRDNs);
	}

	
	public static KeyPair generateKeyPair(int len)
	{
		KeyPairGenerator kpGen;
		try
		{
			kpGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e)
		{
			throw new IllegalStateException("RSA algorithm not supported!?", e);
		}
		kpGen.initialize(len, new SecureRandom());
		return kpGen.generateKeyPair();
	}
}
