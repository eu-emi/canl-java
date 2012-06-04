/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.ocsp.OCSPException;

import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;


/**
 * OCSP checker - uses provided {@link OCSPParametes} to perform OCSP calls using 
 * {@link OCSPCachingClient} and returns the final response. Failures (exceptions) are reported via provided callback.
 * @author K. Benedyczak
 */
public class OCSPVerifier 
{
	private OCSPParametes params;
	private ObserversHandler observers;
	public static String OCSP_CACHE_PFX = "ocspresp_";
	
	public OCSPVerifier(OCSPParametes params, ObserversHandler observers)
	{
		this.params = params;
		this.observers = observers;
	}

	public OCSPResult verify(X509Certificate toCheck, X509Certificate issuerCert) throws SimpleValidationErrorException
	{
		List<OCSPResponder> certResponders = getOCSPUrls(toCheck, issuerCert);
		OCSPResponder[] localResponders = params.getLocalResponders();
		List<OCSPResponder> allResponders = new ArrayList<OCSPResponder>();
		if (params.isPreferLocalResponders())
		{
			Collections.addAll(allResponders, localResponders);
			allResponders.addAll(certResponders);
		} else
		{
			allResponders.addAll(certResponders);
			Collections.addAll(allResponders, localResponders);
		}

		if (allResponders.size() == 0)
			throw new SimpleValidationErrorException(ValidationErrorCode.ocspNoResponder);
		
		File diskCachePath = params.getDiskCachePath() == null ? null : new File(params.getDiskCachePath());
		OCSPCachingClient client = new OCSPCachingClient(params.getCacheTtl(), diskCachePath, 
				OCSP_CACHE_PFX);
		for (int i=0; i<allResponders.size(); i++)
		{
			OCSPResponder responder = allResponders.get(i);
			OCSPResult status;
			
			if (i<allResponders.size()-1)
			{
				try
				{
					status = client.queryForCertificate(responder.getAddress(), toCheck, 
							responder.getCertificate(), null, params.isUseNonce(), 
							params.getConntectTimeout());
				} catch (Exception e)
				{
					observers.notifyObservers(responder.getAddress().toExternalForm(), 
								StoreUpdateListener.OCSP, Severity.WARNING, e);
					continue;
				}				
			} else
			{
				try
				{
					status = client.queryForCertificate(responder.getAddress(), toCheck, 
							responder.getCertificate(), null, params.isUseNonce(), 
							params.getConntectTimeout());
				} catch (IOException e)
				{
					observers.notifyObservers(responder.getAddress().toExternalForm(), 
							StoreUpdateListener.OCSP, Severity.WARNING, e);
					throw new SimpleValidationErrorException(ValidationErrorCode.ocspResponderQueryError,
							responder.getAddress(), e.getMessage());
				} catch (OCSPException e)
				{
					observers.notifyObservers(responder.getAddress().toExternalForm(), 
							StoreUpdateListener.OCSP, Severity.WARNING, e);
					throw new SimpleValidationErrorException(ValidationErrorCode.ocspResponseInvalid,
							responder.getAddress(), e.getMessage());
				} catch (Exception e)
				{
					observers.notifyObservers(responder.getAddress().toExternalForm(), 
							StoreUpdateListener.OCSP, Severity.WARNING, e);
					throw new SimpleValidationErrorException(ValidationErrorCode.ocspOtherError,
							responder.getAddress(), e.toString());
				}
			}
			if (status.getStatus() != OCSPResult.Status.unknown)
				return status;
		}
		return new OCSPResult(OCSPResult.Status.unknown);
	}
	
	protected List<OCSPResponder> getOCSPUrls(X509Certificate certificate, X509Certificate issuerCert) 
			throws SimpleValidationErrorException
	{
		AuthorityInformationAccess authInfoAcc = null;
		byte[] authInfoExt = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
		if (authInfoExt != null)
		{
			ASN1InputStream aIn = new ASN1InputStream(authInfoExt);
			ASN1Sequence seq;
			try
			{
				ASN1OctetString octs = (ASN1OctetString)aIn.readObject();
				aIn = new ASN1InputStream(octs.getOctets());
				seq = ASN1Sequence.getInstance(aIn.readObject());
			} catch (IOException e)
			{
				throw new SimpleValidationErrorException(ValidationErrorCode.ocspOtherError,
						"unknown", "Can't extract Authority Info Access extension: " 
								+ e.toString());
			}
			authInfoAcc = AuthorityInformationAccess.getInstance(seq);
		} else
			return new ArrayList<OCSPResponder>(); 

		List<OCSPResponder> ret = new ArrayList<OCSPResponder>();

		AccessDescription[] ads = authInfoAcc.getAccessDescriptions();
		for (int i = 0; i < ads.length; i++)
		{
			if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp))
			{
				GeneralName name = ads[i].getAccessLocation();
				if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
				{
					String url = ((DERIA5String) name.getName()).getString();
					try
					{
						ret.add(new OCSPResponder(new URL(url), issuerCert));
					} catch (MalformedURLException e)
					{
						observers.notifyObservers(url, StoreUpdateListener.OCSP, Severity.ERROR, 
							new Exception("OCSP responder address in certificate being " +
							"checked is not a valid URL: " + e.getMessage(), e));
					}
				}
			}
		}

		return ret;
	}

}
