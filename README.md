EMI Common Authentication Library provides a foundation code for establishing secure SSL/TLS connections, 
validating certificate chains and dealing with proxy certificates.

It was inspired by requirements of the Grid middleware of the EMI project.

The documentation, manual and JavaDocs are available from the external documentation pages,
which are version specific.

Version 2.4.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.4.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?q=milestone%3Acanl-2.4.0+is%3Aclosed
  - This update contains a single but very important improvement: the directory based validator supports now files containning many PEM files concatenated together, i.e. the format often used in many Linux distro trust anchor stores (as tls-ca-bundle.pem in RedHat and derived).

Version 2.3.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.3.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?q=milestone%3Acanl-2.3.0+is%3Aclosed
  - This update contains one change: update of BC dependency to 1.54 version.

Version 2.2.1:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.2.1/
  - Changes: https://github.com/eu-emi/canl-java/issues?q=milestone%3Acanl-2.2.1+is%3Aclosed
  - This update contains two improvements: better paralelization of truststore handling and a fix for handling the default proxy path length.

Version 2.2.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.2.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?q=milestone%3Acanl-2.2.0+is%3Aclosed
  - This update changes a BouncyCastle dependency to the latest available as of now: 1.52. The official CANL API has not been changed however internal code changed a lot. Besides of this change library building was changed to eliminate javadoc errors on JDK 8 and the sortChain method bug was fixed (#73).
  - Note: due to BouncyCastle changes, the OpenSSL truststore performance is slightly degraded (precisely: CRL checking).

Version 2.1.2:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.1.2/
  - Changes: This is a backport release, providing upstream fixes for the older, BC 1.50 based canl. See https://github.com/eu-emi/canl-java/issues?q=milestone%3Acanl-2.1.2+is%3Aclosed for details.

Version 2.1.1:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.1.1/
  - Changes: this update contains two fixes of the OCSP handling: caching of failing OCSP responders and limited memory usage footprint of the overall OCSP cache.

Version 2.1.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.1.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=10&state=closed
  - This release besides few minor fixes (same as in 1.3.1 and 1.3.2 releases) changes the upstream BouncyCastle library dependency to the latest 1.50 version (from 1.48 used in 2.0.0). This update is not groundbreaking, however one behaviour difference was observed which influences canl: the best-effort method for RFC to Openssl DN conversion will slightly change its behaviour in few cases. As this method is by definition not fully correct (and can't be) there won't be any workaround.

Version 2.0.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.0.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=7&state=closed
  - This release is fairly similar to what 1.3.0 provides in terms of improvements over 1.2.x versions, however it is 
using the Bouncy Castle library in version 1.48. The 1.x branch used the vesion 1.46. 
If you also use the BC API directly, please bear in mind that this is a major change - the BC API has changed A LOT.
Finally at the current moment there is also the latest BC library: version 1.49. CANL 2.0.0 will mostly work with it, 
however there is a known problem regarding openssl DNs conversion. Therefore there will be an official 
update of CANL supporting BC 1.49.

Version 1.3.3:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.3.3/
  - Changes: this update contains two fixes of the OCSP handling: caching of failing OCSP responders and limited memory usage footprint of the overall OCSP cache.

Version 1.3.2:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.3.2/
  - Changes: this update contains a single fix for a regression/bug introduced in the 1.3.1 release: https://github.com/eu-emi/canl-java/issues/65 which is relevant for proxy certificate users.

Version 1.3.1:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.3.1/
  - Changes: this update contains a single bugfix: https://github.com/eu-emi/canl-java/issues/62 which is relevant for proxy certificate users.

Version 1.3.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.3.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=9&state=closed
  - This release backports many of the 2.0.0 (to be released soon) branch to the 1.x compatible version which uses BC 1.46.
In particular: support for Openssl 1.x truststore (new hashes), much better memory management for large truststores, some bugfixes

Version 1.2.1:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.2.1/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=8&state=closed

Version 1.2.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.2.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=4&state=closed

Version 1.1.0:

  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.1.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=5&state=closed


Version 1.0.1:

  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-1.0.1/
  - Changes: NONE - it is the first official release.
