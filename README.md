EMI Common Authentication Library provides a foundation code for establishing secure SSL/TLS connections, 
validating certificate chains and dealing with proxy certificates.

It was inspired by requirements of the Grid middleware of the EMI project.

The documentation, manual and JavaDocs are available from the external documentation pages,
which are version specific.

Version 2.0.0:
  - Docs: http://unicore-dev.zam.kfa-juelich.de/documentation/canl-2.0.0/
  - Changes: https://github.com/eu-emi/canl-java/issues?milestone=7&state=closed
  - This release is fairly similar to what 1.3.0 provides in terms of improvements over 1.2.x versions, however it is 
using the Bouncy Castle library in version 1.48. The 1.x branch used the vesion 1.46. 
If you also use the BC API directly, please bear in mind that this is a major change - the BC API has changed A LOT.
Finally at the current moment there is also the latest BC library: version 1.49. CANL 2.0.0 will mostly work with it, 
however there is a known problem regarding openssl DNs conversion. Therefore there will be an official 
update of CANL supporting BC 1.49.

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
