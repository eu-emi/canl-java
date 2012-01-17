/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.util.Date;

public class CertStatus
{
    public static final int UNREVOKED = 11;

    public static final int UNDETERMINED = 12;

    int certStatus = UNREVOKED;

    Date revocationDate = null;

    /**
     * @return Returns the revocationDate.
     */
    public Date getRevocationDate()
    {
        return revocationDate;
    }

    /**
     * @param revocationDate The revocationDate to set.
     */
    public void setRevocationDate(Date revocationDate)
    {
        this.revocationDate = revocationDate;
    }

    /**
     * @return Returns the certStatus.
     */
    public int getCertStatus()
    {
        return certStatus;
    }

    /**
     * @param certStatus The certStatus to set.
     */
    public void setCertStatus(int certStatus)
    {
        this.certStatus = certStatus;
    }
}
