# PEM Analyser

## Installation and Usage

## Certificate Security and what the Script is Doing 

### Certificate
The creating and managing of X509 Certificates have some security pitfalls. Most important a certificate has to be valid.  
A valid certificate has to fulfill two main requirements:
* The signature of the certificate and of any certificate in the sign chain has to be correct (not checked by 
  the script yet).
* The current date has to be in the timespan defined by the *not valid before* and *not valid after* date fields of the 
  certificate.
* The certificate is not revoked. One method to check if a certificate is revoked is OCSP. Currently, this script do not check 
whether a certificate is revoked or not.

Another important security feature of certificates is the Hash-Algorithm used to create the signature. For example openssl 
currently support several weak algorithm like MD5 or SHA1 which has known weaknesses. Weak hash algorithm create for example 
the thread, that attacker may find a valid signature for a certificate with changed content. The script will mark the 
certificate as security issue, if it uses a SHA1, MD2, RIPEMD128 or MD5 hash algorithm for its signature.

Beside of the chosen hash algorithm the size of the key used to sign the certificate is important for a secure certificate.
The size of the key lenght depend on the chosen encryption algorithm. The german Bundesamt für Sicherheit in der Informationstechnik (BSI) published in 2020 a 
[recommendation](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile) 
on key sizes. Other recommendations can be found at [www.keylength.com](https://www.keylength.com/en/compare/). Currently, 
the script marks a certificate as security issue if the length of public key is shorter than 2048 for RSA and 256 for elliptic 
curves. In upcoming versions it might make sense to consider elliptic curves in a more differentiated way.

To decrease the damage if a certificate and the corresponding private key got lost, the usage of a certificate can be 
explicit defined. This feature was introduced in version 3 for X509 certificates. For example a certificate used to secure a 
ssl connection to a webpage should not be allowed to sign other certificates. This script marks a certificate as security issue, 
if the key usage is not restricted.

Further a certificate can be self-signed. Such a certificate should not be used in general, specially not for a public 
purpose like to secure a ssl connection to a public reachable webpage. Nevertheless, there may be circumstances where it 
may be reasonable to use a self-signed certificate. This script marks a self-signed certifcated as security issue.

### Keyfiles
The principal security factor of a key is its length. As written above the page [www.keylength.com](https://www.keylength.com/en/compare/)
is a good resource for an appropriate key length based on the chosen algorithm. Currently, the script marks a key as 
security issue if the length of the key is shorter than 2048 for RSA and 256 for elliptic curves. In upcoming versions 
it might make sense to consider elliptic curves in a more differentiated way.

Currently, the script can not handle encrypted private keys.
## Further Reading
https://www.keylength.com/en/compare/
https://perspectiverisk.com/multiple-ssl-tls-certificate-weaknesses/  
https://cryptologie.net/article/374/common-x509-certificate-validationcreation-pitfalls/  
https://github.com/golang/go/issues/15194

## Sources
The file server2.pem is copied from https://svn.python.org/projects/external/openssl-1.0.1h/apps/server2.pem
