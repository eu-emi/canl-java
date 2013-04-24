/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.util.Date;

import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;

public class OCSPResult {
	public static enum Status {good, revoked, unknown};
	
	public static final String REASONS[] = {
		"unspecified",
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"unknown",
		"removeFromCRL",
		"privilegeWithdrawn",
		"aACompromise"
	};

	private Status status;
	private Date revocationTime;
	private String revocationReason;

	public OCSPResult(Status status)
	{
		this.status = status;
		if (status == Status.revoked)
			throw new IllegalArgumentException("Can not create OCSPStatus object with " +
					"revoked status without an OCSP reply");
	}
	
	public OCSPResult(SingleResp resp)
	{
		Object rStatus = resp.getCertStatus();
		if (rStatus == null)
			status = Status.good;
		else if (rStatus instanceof UnknownStatus)
			status = Status.unknown;
		else 
		{
			status = Status.revoked;
			RevokedStatus revStatus = (RevokedStatus)rStatus;
			revocationTime = revStatus.getRevocationTime();
			if (revStatus.hasRevocationReason())
				revocationReason = REASONS[revStatus.getRevocationReason()];
			else
				revocationReason = REASONS[0];
		}
	}

	/**
	 * @return the status
	 */
	public Status getStatus()
	{
		return status;
	}

	/**
	 * @return the revocationTime
	 */
	public Date getRevocationTime()
	{
		return revocationTime;
	}

	/**
	 * @return the revocationReason
	 */
	public String getRevocationReason()
	{
		return revocationReason;
	}
	
	@Override
	public String toString()
	{
		if (status != Status.revoked)
			return status.toString();
		return "revoked at " + revocationTime + ((revocationReason != null) ? (" (" + revocationReason +")") 
				: "");  
	}
}
