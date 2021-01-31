/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.emi.security.authn.x509.helpers.ssl.DisabledNameMismatchCallback;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator2;

/**
 * OCSP client is responsible for the network related activity of the OCSP invocation pipeline.
 * This class is state less and thread safe.
 * <p>
 * It is implementing the RFC 2560 also taking care to support the lightweight profile recommendations
 * defined in the RFC 5019.
 * 
 * @author K. Benedyczak
 */
public class OCSPClientImpl
{
	private static final Charset ASCII = Charset.forName("US-ASCII");
	private static final int MAX_RESPONSE_SIZE = 20480;
	
	/**
	 * Returns a verified single response, related to the checked certificate. This is single-shot version, 
	 * which can be used instead of manual invocation of low-level methods.
	 * @param responder mandatory - URL of the responder. HTTP or HTTPs, however in https mode the 
	 * @param toCheckCert mandatory certificate to be checked
	 * @param issuerCert mandatory certificate of the toCheckCert issuer
	 * @param requester if not null, then it is assumed that request must be signed by the requester.
	 * @param addNonce if true nonce will be added to the request and required in response
	 * @param timeout timeout
	 * @return Final OCSP checking result
	 * @throws IOException IO exception
	 * @throws OCSPException OCSP exception
	 */
	public OCSPResult queryForCertificate(URL responder, X509Certificate toCheckCert, 
			X509Certificate issuerCert, X509Credential requester, boolean addNonce, int timeout) 
					throws IOException, OCSPException 
	{
		OCSPReq request = createRequest(toCheckCert, issuerCert, requester, addNonce);
		OCSPResp response = send(responder, request, timeout).getResponse();
		byte[] nonce = null;
		if (addNonce)
			nonce = extractNonce(request);
		SingleResp resp = verifyResponse(response, toCheckCert, issuerCert, nonce);
		return new OCSPResult(resp);
	}


	public OCSPReq createRequest(X509Certificate toCheckCert, 
			X509Certificate issuerCert, X509Credential requester, boolean addNonce) 
					throws OCSPException
	{
		OCSPReqBuilder generator = new OCSPReqBuilder();
		CertificateID certId;
		try
		{
			DigestCalculator digestCalc = new BcDigestCalculatorProvider().get(CertificateID.HASH_SHA1);
			X509CertificateHolder issuerCertHolder = new JcaX509CertificateHolder(issuerCert);
			certId = new CertificateID(digestCalc, issuerCertHolder, toCheckCert.getSerialNumber());
		} catch (OperatorCreationException e1)
		{
			throw new OCSPException("Problem creating digester", e1);
		} catch (CertificateEncodingException e)
		{
			throw new OCSPException("Issuer certificate is unsupported ", e);
		}
		
		generator.addRequest(certId);
		if (addNonce)
		{
			byte[] nonce = new byte[16];
			Random rand = new Random();
			rand.nextBytes(nonce);
			Extensions extensions = new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
					false, new DEROctetString(nonce)));
			generator.setRequestExtensions(extensions);
		}
		if (requester != null)
		{
			X500Name subjectName = new X500Name(requester.getCertificate().getSubjectX500Principal().getName());
			generator.setRequestorName(subjectName);
			try
			{
				JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(
						requester.getCertificate().getSigAlgOID());
				return generator.build(csBuilder.build(requester.getKey()), null);
			} catch (OperatorCreationException e)
			{
				throw new OCSPException("Unsupported signing algorithm when creating a OCSP request?", e);
			}
		} else
		{
			return generator.build();
		}
	}
	
	public OCSPResponseStructure send(URL responder, OCSPReq requestO, int timeout) throws IOException {
		InputStream in = null;
		byte[] request = requestO.getEncoded();
		byte[] response = null;
		Date maxCache = null;
		HttpURLConnection con = null;
		try {
			String getUrl = getHttpGetUrl(responder, request);
			if (getUrl == null)
				con = doPost(responder, request, timeout);
			else
			{
				URL u = new URL(getUrl);
				con = (HttpURLConnection) u.openConnection();
				configureHttpConnection(con, timeout);
			}
			
			in = con.getInputStream();
			int contentLength = con.getContentLength();
			if (contentLength == -1 || contentLength > MAX_RESPONSE_SIZE)
				contentLength = MAX_RESPONSE_SIZE;
			maxCache = getNextUpdateFromCacheHeader(con.getHeaderField("cache-control"));
			response = new byte[contentLength];
			int total = 0;
			int count = 0;
			while (total < contentLength) {
				count = in.read(response, total, response.length - total);
				if (count < 0)
					break;

				total += count;
			}
			if (count >= 0 && in.read() >= 0)
				throw new IOException("OCSP response size exceeded the upper limit of " + 
						MAX_RESPONSE_SIZE);
			if (total != contentLength)
				response = Arrays.copyOf(response, total);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException ioe) {
					throw ioe;
				}
			}
		}
		OCSPResp resp = new OCSPResp(response);
		return new OCSPResponseStructure(resp, maxCache);
	}
	
	private void configureHttpConnection(HttpURLConnection con, int timeout)
	{
		if (con instanceof HttpsURLConnection) 
		{
			HttpsURLConnection httpsCon = (HttpsURLConnection) con;
			BinaryCertChainValidator trustAll = new BinaryCertChainValidator(true);
			SSLSocketFactory sf = new SocketFactoryCreator2(trustAll, new DisabledNameMismatchCallback()).getSocketFactory();
			httpsCon.setSSLSocketFactory(sf);
		}
		con.setConnectTimeout(timeout);
		con.setReadTimeout(timeout);
	}
	
	/**
	 * 
	 * @return null if the encoded request is > 255, or the string which can be used as GET 
	 * request URL with request encoded. 
	 */
	private String getHttpGetUrl(URL responder, byte[] request)
	{
		if (responder.toExternalForm().length() + request.length > 255)
			return null; //as Base64 is making the request even bigger this is a VERY safe bet.
		byte[] base64 = Base64.encode(request);
		String ret = new String(base64, ASCII);
		
		try
		{
			ret = URLEncoder.encode(ret, ASCII.name());
		} catch (UnsupportedEncodingException e)
		{
			throw new RuntimeException("US-ASCII encoding is not known?", e);
		}
		String url = responder.toExternalForm();
		if (url.endsWith("/"))
			ret = url + ret;
		else
			ret = url + "/" + ret;
		
		if (ret.length() > 255)
			return null;
		return ret;
	}
	
	private HttpURLConnection doPost(URL responder, byte[] request, int timeout) throws IOException
	{
		HttpURLConnection con = (HttpURLConnection) responder.openConnection();
		configureHttpConnection(con, timeout);
		
		OutputStream out = null;
		try
		{
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/ocsp-request");
			con.setRequestProperty("Content-length", String.valueOf(request.length));
			out = con.getOutputStream();
			out.write(request);
			out.flush();
			return con;
		} finally {
			if (out != null) {
				try {
					out.close();
				} catch (IOException ioe) {
					throw ioe;
				}
			}
		}
	}

	public static Date getNextUpdateFromCacheHeader(String cc)
	{
		if (cc == null)
			return null;
		int i = cc.indexOf("max-age=");
		if (i == -1)
			return null;
		i+=8;
		int j = cc.indexOf(",", i);
		if (j == -1)
			j=cc.length();
		String deltaS = cc.substring(i, j).trim();
		int delta;
		try
		{
			delta = Integer.parseInt(deltaS);
		}catch (NumberFormatException e)
		{
			return null;
		}
		return new Date(System.currentTimeMillis() + (delta*1000L));
	}
	
	private static String getResponderErrorDesc(int errorNo)
	{
		switch (errorNo)
		{
		case OCSPResponseStatus.INTERNAL_ERROR:
			return "internal server error";
		case OCSPResponseStatus.MALFORMED_REQUEST:
			return "malformed request";
		case OCSPResponseStatus.SIG_REQUIRED:
			return "request is required to be signed";
		case OCSPResponseStatus.TRY_LATER:
			return "try again later";
		case OCSPResponseStatus.UNAUTHORIZED:
			return "request was not authorized";
		default:
			return "unknown error";
		
		}
	}
	
	/**
	 * Verifies the provided response
	 * @param response OCSP response
	 * @param toCheckCert mandatory certificate to be checked
	 * @param issuerCert mandatory certificate of the toCheckCert issuer
	 * @param checkNonce expected OCSP nonce
	 * @return verified response corresponding to the certificate being checked
	 * @throws OCSPException OCSP exception
	 */
	public SingleResp verifyResponse(OCSPResp response, X509Certificate toCheckCert,
			X509Certificate issuerCert, byte[] checkNonce) throws OCSPException
	{
		if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL)
			throw new OCSPException("Responder returned an error: " + 
					getResponderErrorDesc(response.getStatus()));  		
		Object respO = response.getResponseObject();
		if (!(respO instanceof BasicOCSPResp))
				throw new OCSPException("Only Basic OCSP response type is supported");
		BasicOCSPResp bresp = (BasicOCSPResp) respO;
		
		//version, producedAt and responderID are ignored.
		if (checkNonce != null)
		{
			byte[] nonceAsn;
			try
			{
				nonceAsn = bresp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).
						getExtnValue().getEncoded();
			} catch (IOException e1)
			{
				throw new OCSPException("Can't parse OCSP nonce extension", e1);
			}
			if (nonceAsn == null)
				throw new OCSPException("Nonce was sent and is required but did not get it in reply");
			ASN1OctetString octs;
			try
			{
				octs = (ASN1OctetString)ASN1Primitive.fromByteArray(nonceAsn);
			} catch (Exception e)
			{
				throw new OCSPException("Nonce received with the reply is invalid, " +
						"unable to parse it", e);
			}
			byte[] nonce = octs.getOctets();
			if (!Arrays.equals(nonce, checkNonce))
				throw new OCSPException("Received nonce doesn't match the one sent to the server. " +
						"Sent: " + Arrays.toString(checkNonce) + " received: " + 
						Arrays.toString(nonce));
		}

		PublicKey key = establishResponsePubKey(bresp, issuerCert);
		try
		{
			ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().build(key);
			if (!bresp.isSignatureValid(verifierProvider))
				throw new OCSPException("Failed to verify the OCSP response signature. " +
						"It is corrupted or faked");
		} catch (OperatorCreationException e)
		{
			throw new OCSPException("The OCSP is signed with unsupported key: " +
					"can not verify its signature", e);
		}
		
		if (bresp.getCriticalExtensionOIDs().size() > 0)
			throw new OCSPException("OCSP contains unsupported critical extensions: " + 
					bresp.getCriticalExtensionOIDs());
		
		SingleResp[] resps = bresp.getResponses();
		for (int i=0; i<resps.length; i++)
		{
			SingleResp sResp = resps[i];
			if (sResp.getCriticalExtensionOIDs().size() > 0)
				throw new OCSPException("OCSP SingleResponse contains unsupported critical extensions: " + 
						sResp.getCriticalExtensionOIDs());
			
			if (!checkCertIDMatching(toCheckCert, issuerCert, sResp.getCertID()))
				continue;
		
			verifyTimeRange(sResp.getThisUpdate(), sResp.getNextUpdate());

			return sResp;
		}
		throw new OCSPException("Received a correct answer from OCSP responder, but it didn't contain " +
				"any information on the certificate being checked");
	}
	
	private void verifyTimeRange(Date thisUpdate, Date nextUpdate) throws OCSPException
	{
		Date now = new Date();
		if (thisUpdate == null)
			throw new OCSPException("Malformed OCSP response, no thisUpdate time");
		if (nextUpdate == null)
			throw new OCSPException("Unsupported OCSP response, no nextUpdate time (required by RFC 5019)");
		int tolerance = 120000; //two minutes
		
		Date futureNow = new Date(now.getTime() + tolerance);
		Date pastNow = new Date(now.getTime() - tolerance);

		if (futureNow.before(thisUpdate))
			throw new OCSPException("Response is not yet valid, will be from: " + thisUpdate);
			
		if (pastNow.after(nextUpdate))
			throw new OCSPException("Response has expired on: " + nextUpdate);
	}
	
	private boolean checkCertIDMatching(X509Certificate toFind, X509Certificate issuerCert, 
			CertificateID checkedCertId) throws OCSPException
	{
		try
		{
			JcaX509CertificateHolder issuerCertHolder = new JcaX509CertificateHolder(issuerCert);
			DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(
					checkedCertId.getHashAlgOID()));
			CertificateID certId = new CertificateID(digCalc, issuerCertHolder, 
					toFind.getSerialNumber());
			return certId.getHashAlgOID().equals(checkedCertId.getHashAlgOID()) &&
					Arrays.equals(certId.getIssuerKeyHash(), checkedCertId.getIssuerKeyHash()) &&
					Arrays.equals(certId.getIssuerNameHash(), checkedCertId.getIssuerNameHash());
		} catch (OperatorCreationException e)
		{
			throw new OCSPException("Cant get digester for the checked certificate, the algorithm " +
					"is: " + checkedCertId.getHashAlgOID(), e);
		} catch (CertificateEncodingException e)
		{
			throw new OCSPException("Issuer certificate is unsupported", e);
		}
	}
	
	private PublicKey establishResponsePubKey(BasicOCSPResp bresp, X509Certificate issuerCert) throws OCSPException
	{
		X509CertificateHolder[] signerCerts = bresp.getCerts();
		if (signerCerts == null || signerCerts.length == 0)
			return issuerCert.getPublicKey();
		X509Certificate signerCert;
		try
		{
			signerCert = new JcaX509CertificateConverter().getCertificate(signerCerts[0]);
		} catch (CertificateException e1)
		{
			throw new OCSPException("Can't unwrap signer's certificate from the BasicOCSPResp", e1);
		} 
				
		if (signerCert.equals(issuerCert))
			return issuerCert.getPublicKey();
		
		//ok - now we have the last possibility - delegated OCSP responder
		if (!issuerCert.getSubjectX500Principal().equals(signerCert.getIssuerX500Principal()))
			throw new OCSPException("Response is signed by an untrusted/invalid entity: " +
					CertificateUtils.format(signerCert, FormatMode.COMPACT_ONE_LINE));
		try
		{
			List<String> keyUsage = signerCert.getExtendedKeyUsage();
			if (keyUsage == null || !keyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) 
				throw new OCSPException("Response is signed by an entity which does not have the " +
						"OCSP delegation from the CA (no flag in ExtendedKeyUsage)");
		} catch (CertificateParsingException e)
		{
			throw new OCSPException("Response contains an unparsable certificate (ExtendedKeyUsage)", e);
		}

		try
		{
			signerCert.verify(issuerCert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
		} catch (Exception e)
		{
			throw new OCSPException("Response contains a certificate which is improperly signed, " +
					"it is faked or corrupted: " + e.getMessage(), e);
		}
		
		return signerCert.getPublicKey();	
	}
	
	
	public static byte[] extractNonce(OCSPReq request) throws IOException
	{
		Extension nonceExt = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		if (nonceExt == null)
			return null;
		byte[] nonceAsn = nonceExt.getExtnValue().getEncoded();
		if (nonceAsn == null)
			return null;
		ASN1OctetString octs;
		try
		{
			octs = (ASN1OctetString)ASN1Primitive.fromByteArray(nonceAsn);
		} catch (Exception e)
		{
			throw new IllegalStateException("Can't decode nonce encoded in request", e);
		}
		return octs.getOctets();			
	}
}











