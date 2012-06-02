/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ocsp;

import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

public enum OCSPStatus {
	good, revoked, unknown;
	
	public static OCSPStatus getFromResponse(SingleResp resp)
	{
		Object status = resp.getCertStatus();
		if (status == null)
			return OCSPStatus.good;
		else if (status instanceof UnknownStatus)
			return OCSPStatus.unknown;
		else
			return OCSPStatus.revoked;
	}
}
