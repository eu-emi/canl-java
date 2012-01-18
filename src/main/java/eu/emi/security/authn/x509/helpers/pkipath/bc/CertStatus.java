/*
 * This class is copied from the BouncyCastle library, version 1.46.
 * See FixedBCPKIXCertPathReviewer in this package for extra information
 * 
 * Of course code is licensed and copyrighted by the BC:
 * 
 * 
Copyright (c) 2000 - 2011 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE.
 *  
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
