---
title: "CBOR Encoding of X.509 Certificates (CBOR Certificates)"
docname: draft-mattsson-cose-cbor-cert-compress-latest

ipr: trust200902
cat: std

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: S. Raza
        name: Shahid Raza
        org: RISE AB
        email: shahid.raza@ri.se
      -
        ins: J. Höglund
        name: Joel Höglund
        org: RISE AB
        email: joel.hoglund@ri.se
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Preuß Mattsson
        org: Ericsson AB
        email: john.mattsson@ericsson.com
      -
        ins: M. Furuhed
        name: Martin Furuhed
        org: Nexus Group
        email: martin.furuhed@nexusgroup.com

        
normative:

  RFC2119:
  RFC5280:
  RFC7049:
  RFC7925:
  RFC8152:
  RFC8174:
  RFC8446:
  RFC8610:
  RFC8742:
  I-D.ietf-tls-dtls13:
  I-D.ietf-tls-certificate-compression:

informative:

  RFC7228:
  I-D.ietf-cose-x509:
  I-D.ietf-lake-edhoc:

  X.509-IoT:
    target: https://doi.org/10.1007/978-3-319-93797-7_14
    title: Lightweight X.509 Digital Certificates for the Internet of Things.
    seriesinfo:
      "Springer, Cham.": "Lecture Notes of the Institute for Computer Sciences, Social Informatics and Telecommunications Engineering, vol 242."
    author:
      -
        ins: F. Forsby
      -
        ins: M. Furuhed
      -
        ins: P. Papadimitratos
      -
        ins: S. Raza
    date: July 2018

  SECG:
    title: Elliptic Curve Cryptography, Standards for Efficient Cryptography Group, ver. 2
    target: https://secg.org/sec1-v2.pdf
    date: 2009

--- abstract

This document specifies a CBOR encoding of PKIX profiled X.509 Certificates. The resulting certificates are called "CBOR certificates". The CBOR encoding supports a large subset of RFC 5280, while at the same time producing very small sizes for certificates compatible with RFC 7925. The CBOR encoding can be used to compress DER encoded X.509 certificated to encode natively signed certificated. When uses to compress DER encoded X.509 certificates, the CBOR encoding can in many cases compress RFC 7925 profiled certificates with over 50%. The document also specifies COSE headers for CBOR certificates as well as a TLS certificate type for CBOR certificates.

--- middle

# Introduction  {#intro}

One of the challenges with deploying a Public Key Infrastructure (PKI) for the Internet of Things (IoT) is the size and encoding of X.509 public key certificates {{RFC5280}}, since those are not optimized for constrained environments {{RFC7228}}. More compact certificate representations are desirable. Due to the current PKI usage of DER encoded X.509 certificates, keeping compatibility with DER encoded X.509 is necessary at least for a transition period. However, the use of a more compact encoding with the Concise Binary Object Representation (CBOR) {{RFC7049}} reduces the certificate size significantly which has known performance benefits in terms of decreased communication overhead, power consumption, latency, storage, etc.

CBOR is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g. encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. The Concise Data Definition Language (CDDL) {{RFC8610}} provides a way to express structures for protocol messages and APIs that use CBOR. {{RFC8610}} also extends the diagnostic notation.

CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme, where the three highest order bits of the initial byte contain information about the major type. CBOR supports several different types of data items, in addition to integers (int, uint), simple values (e.g. null), byte strings (bstr), and text strings (tstr), CBOR also supports arrays \[\] of data items, maps \{\} of pairs of data items, and sequences of data items. For a complete specification and examples, see {{RFC7049}}, {{RFC8610}}, and  {{RFC8742}}.

RFC 7925 {{RFC7925}} specifies a certificate profile for Internet of Things deployments which can be applied for lightweight certificate based authentication with e.g. TLS {{RFC8446}}, DTLS {{I-D.ietf-tls-dtls13}}, COSE {{RFC8152}}, or EDHOC {{I-D.ietf-lake-edhoc}}. This document specifies a CBOR encoding which can support large parts of {{RFC5280}} based on {{X.509-IoT}}. The encoding support all {{RFC7925}} profiled X.509 certificates. Two variants are defined using exactly the same CBOR encoding and differing only in what is being signed: 

* CBOR compression of DER ecoded X.509 certificates {{RFC5280}}, which can be decompressed into the original DER ecoded X.509 certificate.

* Natively signed CBOR certificates, which further optimizes the performance in constrained environments but is not backwards compatible with {{RFC5280}}, see {{native-CBOR}}. 

This document specifies COSE headers for use of the CBOR certificates with COSE, see {{cose}}. The document also specifies a TLS certificate type for use of the CBOR certificates with TLS (with or without additional TLS certificate compression), see {{tls}}.

# Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

This specification makes use of the terminology in {{RFC5280}}, {{RFC7049}}, {{RFC7228}}, and {{RFC8610}}.

# CBOR Encoding {#encoding}

This section specifies the content and encoding for CBOR certificates, with the overall objective to produce a very compact representation of the certificate profile defined in {{RFC7925}}. The CBOR certificate can be either a CBOR compressed X.509 certificate, in which case the signature is calculated on the DER encoded ASN.1 data in the X.509 certificate, or a natively signed CBOR certificate, in which case the signature is calculated directly on the CBOR encoded data (see {{native-CBOR}}). In both cases the certificate content is adhering to the restrictions given by {{RFC5280}}. When used as for compression of an existing X.509 certificate, the encoding only works on canonical encoded certificates. The encoding is known to work with DER, but might work with other canonical encodings. The compression does not work for BER encoded certificates. 

## Message Fields

In the CBOR encoding, static fields are elided, and elliptic curve points are compressed, OID are replaced with short integers, time values are compressed, and reduntant encoding is removed. Combining these different components reduces the certificate size significantly, which is not possible with general purpose compressions algorithms, see {{fig-table}}. The X.509 fields and their CBOR encodings are listed below.

CBOR certificates are defined in terms of DER encoded {{RFC5280}} X.509 certificates:

* version. The 'version' field is known (fixed to v3), and is omitted in the CBOR encoding.

* serialNumber. The 'serialNumber' INTEGER value field is encoded as a CBOR byte string. Any leading 0x00 byte (to indicate that the number is not negative) is omitted.

* signatureAlgorithm. The 'signatureAlgorithm' field is encoded as a CBOR int (see {{sigalg}}). Algorithms with parameters are not supported. Note that some RSA algorithms use parameters = NULL instead of omitting parameters.

* signature. The 'signature' field is always the same as the 'signatureAlgorithm' field and always omitted from the CBOR encoding.

* issuer. In the general case, the sequence of 'RelativeDistinguishedName' is encoded as CBOR array of CBOR maps, where each AttributeTypeAndValue is encoded as a (CBOR int, CBOR text string) pair. Each AttributeType is encoded as a CBOR int (see {{fig-attrtype}}), where the sign is used to represent the character string type; positive for utf8String, negative for printableString. If exacly one 'RelativeDistinguishedName' is present, the array is omitted and issuer is encoded as a CBOR map. If a RelativeDistinguishedName contains a single AttributeTypeAndValue containing an utf8String encoded 'common name', the AttributeValue is encoded as a CBOR text string. If the utf8String encoded 'common name' contains an EUI-64 mapped from a 48-bit MAC address it is encoded as a CBOR byte string of length 6. Other EUI-64 is encoded as a CBOR byte string of length 8.

* validity. The 'notBefore' and 'notAfter' fields are ASCII string of the form "yymmddHHMMSSZ" for UTCTime and "yyyymmddHHMMSSZ" for GeneralizedTime. They are encoded as unsigned integers using the following invertible encoding (Horner's method with different bases).

   n = SS + 61 * (MM + 60 * (HH + 24 * (dd + 32 * (mm + 13 * yy))))
   
   n = SS + 61 * (MM + 60 * (HH + 24 * (dd + 32 * (mm + 13 * yyyy))))

   They are encoded as a byte string, which is interpreted as an unsigned integer n in network byte order. UTCTime and GeneralizedTime are encoded as a byte strings of length 4 and 5 respectivly. Decoding can be done by a succession of modulo and substraction operations. I.e. SS = n mod 61, MM = ((n - SS) / 61) mod 60, etc.

* subject. The 'subject' is encoded exactly like issuer.

* subjectPublicKeyInfo.  The 'algorithm' field is encoded as a CBOR int (see {{pkalg}}). Algorithms with parameters are not supported with the exception of id-ecPublicKey where the namedCurve parameter is encoded in the CBOR int. Note that some RSA algorithms use parameters = NULL instead of omitting parameters. The 'subjectPublicKey' BIT STRING value field is encoded as a CBOR byte string. This specification assume the BIT STRING has zero unused bits and the length of the CBOR byte string will therefore in general be at least one byte shorter than the lenght of the BIT STRING. Public keys of type id-ecPublicKey are point compressed as defined in Section 2.3.3 of {{SECG}} and are therefore much shorter.

* extensions. The 'extensions' field is encoded as a CBOR array where each extension is represented with an int. The extensions mandated to be supported by {{RFC7925}} is encodeded as specified in {{ext-encoding}}. If exacly one 'Extension' is present, the array is omitted.

* signatureValue. The 'signatureValue' BIT STRING value field is encoded as a CBOR byte string. This specification assume the BIT STRING has zero are zero unused bits and the length of the CBOR byte string will therefore in general be at least one byte shorter than the lenght of the BIT STRING. ECDSA Signatures are compressed (padding and extra length fields which are present in the ASN.1 encoding are omitted) and are therefore much shorter. For natively signed CBOR certificates the signatureValue is calculated over the certificate CBOR sequence excluding the signatureValue.

In addition to the above fields present in X.509, the CBOR encoding introduces an additional field:

* type. A CBOR int used to indicate the type of CBOR certificate. Currently, type can be a natively signed CBOR certificate (type = 0) or a CBOR compressed X.509 certificates (type = 1), see {{type}}.

The following Concise Data Definition Language (CDDL) defines CBORCertificate and TBSCertificate as groups, which are encoded as CBOR Sequences {{RFC8742}}. The member names therefore only have documentary value.


~~~~~~~~~~~ CDDL
; This defines an array, the elements of which are to be used in a CBOR Sequence:
CBORCertificate = [
   tbsCertificate : TBSCertificate,
   signatureValue : bytes,
]

TBSCertificate = (
   type : int,
   serialNumber : bytes,
   issuerSignatureAlgorithm : int,
   issuer : Name,
   validityNotBefore: bytes,
   validityNotAfter: bytes,
   subject : Name,
   subjectPublicKeyAlgorithm : int,
   subjectPublicKey : bytes,
   extensions : [ * Extension ] / int,
)

Name = [ * RelativeDistinguishedName ] / RelativeDistinguishedName

RelativeDistinguishedName = [ + AttributeTypeAndValue ] / text / bytes

AttributeTypeAndValue = (
   type: int,
   value: text,
)

Extension = (int, ? bytes) 
~~~~~~~~~~~

## Encoding of Extensions {#ext-encoding}

NOTE: The discussions in the COSE WG seems to indicate that a much larger set of extensions should be supported. This will likely result in a completly different encoding than the one below, which is very {{RFC7925}} focused.

This section details the encoding of the 'extensions' field. Each extension is represented with an int. Critical extensions are encoded with a negative sign. The boolean values (digitalSignature, keyAgreement, etc.) are set to 0 or 1 according to their value in the DER encoding. If the array contains a single int, 'extensions' is encoded as the int instead of an array.  pathLenConstraint is limited to a max value of 10. If subjectAltName is present, the value is placed after the int the end of the array encoded as a byte or text string following the encoding rules for the subject field.

~~~~~~~~~~~
   subjectAltName = 1
~~~~~~~~~~~
~~~~~~~~~~~
   basicConstraints = 2 + pathLenConstraint
~~~~~~~~~~~
~~~~~~~~~~~
   keyUsage = 12 + digitalSignature
            + 2 * keyAgreement + 4 * keyCertSign
~~~~~~~~~~~
~~~~~~~~~~~
   extKeyUsage = 19 + id-kp-serverAuth + 2 * id-kp-clientAuth
               + 4 * id-kp-codeSigning + 8 * id-kp-OCSPSigning
~~~~~~~~~~~

Consequently: 

* A non-critical subjectAltName is encoded as 1. A critical subjectAltName is encoded as -1.

* A critical basicConstraints (cA = 1) without pathLenConstraint is encoded as -2.

* A non-critical keyUsage (digitalSignature = 0, keyAgreement = 1, keyCertSign = 0) is encoded as 14 (= 12 + 2). 

* A non-criticical extKeyUsage (id-kp-serverAuth = 0, id-kp-clientAuth = 0, id-kp-codeSigning = 1, id-kp-OCSPSigning = 1) is encoded as 31 (= 19 + 4 + 8). 

Thus, a critical basicConstraints (cA = 1) followed by a non-critical keyUsage (digitalSignature = 0, keyAgreement = 1, keyCertSign = 0) is encoded as \[-2, 14\]. A single critical subjectAltName (dNSName = "for.example") is encoded as \[-1, "for.example"\].

# Compliance Requirements for Constrained IoT

For general purpose applications, the normative requirements of {{RFC5280}} applies. This section describes the mandatory to implement algorithms and OIDs for constrained IoT application; the values of the OIDs including certificate fields and extensions, time format, attributes in distinguished names, etc.

TODO: Write this section

# Deployment settings {#dep-set}

CBOR certificates can be deployed with legacy X.509 certificates and CA infrastructure. In order to verify the signature, the CBOR certificate is used to recreate the original X.509 data structure to be able to verify the signature.

For protocols like TLS/DTLS 1.2, where the handshake is sent unencrypted, the actual encoding and compression can be done at different locations depending on the deployment setting. For example, the mapping between CBOR certificate and standard X.509 certificate can take place in a 6LoWPAN border gateway which allows the server side to stay unmodified. This case gives the advantage of the low overhead of a CBOR certificate over a constrained wireless links. The conversion to X.509 within an IoT device will incur a computational overhead, however, measured in energy this is negligible compared to the reduced communication overhead.

For the setting with constrained server and server-only authentication, the server only needs to be provisioned with the CBOR certificate and does not perform the conversion to X.509. This option is viable when client authentication can be asserted by other means.

For protocols like IKEv2, TLS/DTLS 1.3, and EDHOC, where certificates are encrypted, the proposed encoding needs to be done fully end-to-end, through adding the encoding/decoding functionality to the server.

# Expected Certificate Sizes

The CBOR encoding of the sample certificate given in {{appA}} results in the numbers shown in {{fig-table}}. After {{RFC7925}} profiling, most duplicated information has been removed, and the remaining text strings are minimal in size. Therefore the further size reduction reached with general compression mechanisms will be small, mainly corresponding to making the ASN.1 endcoding more compact. The zlib number was calculated with zlib-flate.

~~~~~~~~~~~
zlib-flate -compress < cert.der > cert.compressed
~~~~~~~~~~~

~~~~~~~~~~~
+------------------+--------------+------------+--------------------+
|                  |   RFC 7925   |    zlib    |  CBOR Certificate  |
+------------------+---------------------------+--------------------+
| Certificate Size |     314      |     295    |         138        |
+------------------+--------------+------------+--------------------+
~~~~~~~~~~~
{: #fig-table title="Comparing Sizes of Certificates (bytes)"}
{: artwork-align="center"}

# Natively Signed CBOR Certificates {#native-CBOR}

The difference between CBOR compressed X.509 certificate and natively signed CBOR certificate is that the signature is calculated over the CBOR encoding of the CBOR sequence tbsCertficate rather than the DER encoded ASN.1 data. This removes entirely the need for ASN.1 DER and base64 encoding which reduces the processing in the authenticating devices, and avoids known complexities with these encodings.

Natively signed CBOR certificates can be applied in devices that are only required to authenticate to natively signed CBOR certificate compatible servers.
This is not a major restriction for many IoT deployments, where the parties issuing and verifying certificates can be a restricted ecosystem which not necessarily involves public CAs.

CBOR compressed X.509 certificates provides an intermediate step between {{RFC7925}} profiled X.509 certificates and natively signed CBOR certificates: An implementation of CBOR compressed X.509 certificates contains both the CBOR encoding of the X.509 certificate and the signature operations sufficient for natively signed CBOR certificates.


# Security Considerations  {#sec-cons}

The CBOR profiling of X.509 certificates does not change the security assumptions needed when deploying standard X.509 certificates but decreases the number of fields transmitted, which reduces the risk for implementation errors.

Conversion between the certificate formats can be made in constant time to reduce risk of information leakage through side channels.

The mechanism in this draft does not reveal any additional information compared to X.509. Because of difference in size, it will be possible to detect that this profile is used. The gateway solution described in {{dep-set}} requires unencrypted certificates and is not recommended.

# IANA Considerations  {#iana}

For all items, the 'Reference' field points to this document.

## CBOR Certificate Types Registry {#type}

IANA has created a new registry titled "CBOR Certificate Types" under the new heading "CBOR Certificate". The registration procedure is "Expert Review". The columns of the registry are Value, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~
+-------+---------------------------------------+
| Value | Description                           |
+=======+=======================================+
|     0 | Natively Signed CBOR Certificate      |
|     1 | CBOR Compressed X.509 Certificate     |
+-------+---------------------------------------+
~~~~~~~~~~~
{: #fig-types title="CBOR Certificate Types"}
{: artwork-align="center"}

## CBOR Attribute Type Registry {#atttype}

IANA has created a new registry titled "CBOR Attribute Type Registry" under the new heading "CBOR Certificate". The columns of the registry are Value, X.509 Attribute Type, and Reference, where Value is an integer and the other columns are text strings. Only positive values can be regisrered. For values in the inteval [1, 23] the registration procedure is "IETF Review". For all other values the registration procedure is "Expert Review". The initial contents of the registry are:

~~~~~~~~~~~
+-------+---------------------------------------+
| Value | X.509 Attribute Type                  |
+=======+=======================================+
|     1 | id-at-commonName                      |
|     2 | id-at-surname                         |
|     3 | id-at-serialNumber                    |
|     4 | id-at-countryName                     |
|     5 | id-at-localityName                    |
|     6 | id-at-stateOrProvinceName             |
|     7 | id-at-organizationName                |
|     8 | id-at-organizationalUnitName          |
|     9 | id-at-title                           |
|    10 | id-at-givenName                       |
|    11 | id-at-initials                        |
|    12 | id-at-generationQualifier             |
|    13 | id-at-dnQualifier                     |
|    14 | id-at-pseudonym                       |
+-------+---------------------------------------+
~~~~~~~~~~~
{: #fig-attrtype title="CBOR Attribute Type Registry"}
{: artwork-align="center"}

## CBOR Certificate Signature Algorithms Registry {#sigalg}

IANA has created a new registry titled "CBOR Certificate Signature Algorithms" under the new heading "CBOR Certificate". For values in the inteval [-24, 23] the registration procedure is "IETF Review". For all other values the registration procedure is "Expert Review". The columns of the registry are Value, X.509 Algorithm, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~
+-------+---------------------------------------+
| Value | X.509 Signature Algorithm             |
+=======+=======================================+
|   -24 | sha1WithRSAEncryption                |
|   -23 | sha224WithRSAEncryption               |
|   -22 | sha256WithRSAEncryption               |
|   -21 | sha384WithRSAEncryption               |
|   -20 | sha512WithRSAEncryption               |
|   -19 | id-rsassa-pkcs1-v1_5-with-sha3-224    |
|   -18 | id-rsassa-pkcs1-v1_5-with-sha3-256    |
|   -17 | id-rsassa-pkcs1-v1_5-with-sha3-384    |
|   -16 | id-rsassa-pkcs1-v1_5-with-sha3-512    |
|   -15 | id-RSASSA-PSS-SHAKE128                |
|   -14 | id-RSASSA-PSS-SHAKE256                |  
|   -13 | ecdsa-with-SHA1                       |
|   -12 | ecdsa-with-SHA224                     |
|   -11 | ecdsa-with-SHA256                     |
|   -10 | ecdsa-with-SHA384                     |
|    -9 | ecdsa-with-SHA512                     |
|    -8 | id-ecdsa-with-sha3-224                |
|    -7 | id-ecdsa-with-sha3-256                |
|    -6 | id-ecdsa-with-sha3-384                |
|    -5 | id-ecdsa-with-sha3-512                |
|    -4 | id-ecdsa-with-shake128                |
|    -3 | id-ecdsa-with-shake256                |
|    -2 | id-Ed25519                            |
|    -1 | id-Ed448                              |
|     0 | id-alg-hss-lms-hashsig                |
|     1 | id-alg-xmss                           |
|     2 | id-alg-xmssmt                         |
+-------+---------------------------------------+
~~~~~~~~~~~
{: #fig-sigalgs title="CBOR Certificate Signature Algorithms"}
{: artwork-align="center"}

## CBOR Certificate Public Key Algorithms Registry {#pkalg}

IANA has created a new registry titled "CBOR Certificate Public Key Algorithms" under the new heading "CBOR Certificate". For values in the inteval [-24, 23] the registration procedure is "IETF Review". For all other values the registration procedure is "Expert Review". The columns of the registry are Value, X.509 Algorithm, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~
+-------+---------------------------------------+
| Value | X.509 Public Key Algorithm            |
+=======+=======================================+
|   -24 | rsaEncryption                         |
|   -23 | id-ecPublicKey + secp256r1            |
|   -22 | id-ecPublicKey + secp384r1            |
|   -21 | id-ecPublicKey + secp521r1            |
|   -20 | id-X25519                             |
|   -19 | id-X448                               |
|   -18 | id-Ed25519                            |
|   -17 | id-Ed448                              |  
|   -16 | id-alg-hss-lms-hashsig                |
|   -15 | id-alg-xmss                           |
|   -14 | id-alg-xmssmt                         |
+-------+---------------------------------------+
~~~~~~~~~~~
{: #fig-pkalgs title="CBOR Certificate Public Key Algorithms"}
{: artwork-align="center"}

## COSE Header Parameters Registry {#cose}

This document registers the following entries in the "COSE Header Parameters" registry under the "CBOR Object Signing and Encryption (COSE)" heading. The formatting and processing are the same as the corresponding x5chain and x5u defined in {{I-D.ietf-cose-x509}} except that the certificates are CBOR encoded instead of DER encoded.

~~~~~~~~~~~
+-----------+-------+----------------+---------------------+
| Name      | Label | Value Type     | Description         |
+===========+=======+================+=====================+
| CBORchain |  TBD1 | COSE_CBOR_Cert | An ordered chain of |
|           |       |                | CBOR certificates   |
+-----------+-------+----------------+---------------------+
| CBORu     |  TBD2 | uri            | URI pointing to a   |
|           |       |                | CBOR certificate    |
+-----------+-------+----------------+---------------------+
~~~~~~~~~~~

## TLS Certificate Types Registry {#tls}

This document registers the following entry in the "TLS Certificate Types" registry under the "Transport Layer Security (TLS) Extensions" heading.

EDITOR'S NOTE: The TLS registrations should be discussed and approved by the TLS WG at a later stage. When COSE WG has adopted work on CBOR certificates, it could be presented in the TLS WG. The TLS WG might e.g. want a separate draft.

~~~~~~~~~~~
+-------+------------------+-------------+---------+
| Value | Name             | Recommended | Comment |
+=======+==================+=============+=========+
|  TBD3 | CBOR Certificate |           Y |         |         
+-------+------------------+-------------+---------+
~~~~~~~~~~~

--- back

# Example CBOR Certificates {#appA}

## Example X.509 Certificate

Example of {{RFC7925}} profiled X.509 certificate parsed with OpenSSL.

~~~~~~~~~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 128269 (0x1f50d)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=RFC test CA
        Validity
            Not Before: Jan  1 00:00:00 2020 GMT
            Not After : Feb  2 00:00:00 2021 GMT
        Subject: CN=01-23-45-FF-FE-67-89-AB
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ae:4c:db:01:f6:14:de:fc:71:21:28:5f:dc:7f:
                    5c:6d:1d:42:c9:56:47:f0:61:ba:00:80:df:67:88:
                    67:84:5e:e9:a6:9f:d4:89:31:49:da:e3:d3:b1:54:
                    16:d7:53:2c:38:71:52:b8:0b:0d:f3:e1:af:40:8a:
                    95:d3:07:1e:58
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:37:38:73:ef:87:81:b8:82:97:ef:23:5c:1f:ac:
         cf:62:da:4e:44:74:0d:c2:a2:e6:a3:c6:c8:82:a3:23:8d:9c:
         02:20:3a:d9:35:3b:a7:88:68:3b:06:bb:48:fe:ca:16:ea:71:
         17:17:34:c6:75:c5:33:2b:2a:f1:cb:73:38:10:a1:fc
         
~~~~~~~~~~~

The DER encoding of the above certificate is 314 bytes.

~~~~~~~~~~~
308201363081DEA003020102020301F50D300A06082A8648CE3D040302301631
14301206035504030C0B5246432074657374204341301E170D32303031303130
30303030305A170D3231303230323030303030305A30223120301E0603550403
0C1730312D32332D34352D46462D46452D36372D38392D41423059301306072A
8648CE3D020106082A8648CE3D03010703420004AE4CDB01F614DEFC7121285F
DC7F5C6D1D42C95647F061BA0080DF678867845EE9A69FD4893149DAE3D3B154
16D7532C387152B80B0DF3E1AF408A95D3071E58A30F300D300B0603551D0F04
0403020780300A06082A8648CE3D04030203470030440220373873EF8781B882
97EF235C1FACCF62DA4E44740DC2A2E6A3C6C882A3238D9C02203AD9353BA788
683B06BB48FECA16EA71171734C675C5332B2AF1CB733810A1FC
~~~~~~~~~~~

## Example CBOR Certificate Compression

The CBOR certificate compression of the X.509 in CBOR diagnostic format is:

~~~~~~~~~~~
/This defines an array, the elements of which are to be used in a CBOR Sequence:/
[
  1,
  h'01f50d',
  -11,
  "RFC test CA",
  h'2B044180',
  h'2D543300',
  h'0123456789AB',
  -23,
  h'02ae4cdb01f614defc7121285fdc7f5c6d1d42c95647f061ba
    0080df678867845e',
  5,
  h'373873EF8781B88297EF235C1FACCF62DA4E44740DC2A2E6A3
    C6C882A3238D9C3AD9353BA788683B06BB48FECA16EA711717
    34C675C5332B2AF1CB733810A1FC'
]
~~~~~~~~~~~

The CBOR encoding (CBOR sequence) of the CBOR certificate is 138 bytes.

~~~~~~~~~~~
014301F50D2A6B5246432074657374204341442B044180442D54330046012345
6789AB36582102AE4CDB01F614DEFC7121285FDC7F5C6D1D42C95647F061BA00
80DF678867845E055840373873EF8781B88297EF235C1FACCF62DA4E44740DC2
A2E6A3C6C882A3238D9C3AD9353BA788683B06BB48FECA16EA71171734C675C5
332B2AF1CB733810A1FC
~~~~~~~~~~~

## Example: Natively Signed CBOR Certificate

The corresponding natively signed CBOR certificate in CBOR diagnostic format is identical except for type and signatureValue.

~~~~~~~~~~~
/This defines an array, the elements of which are to be used in a CBOR Sequence:/
[
  0,
  h'01f50d',
  -11,
  "RFC test CA",
  h'2B044180',
  h'2D543300',
  h'0123456789AB',
  -23,
  h'02ae4cdb01f614defc7121285fdc7f5c6d1d42c95647f061
    ba0080df678867845e',
  5,
  h'7F10A063DA8DB2FD49414440CDF85070AC22A266C7F1DFB1
    577D9A35A295A8742E794258B76968C097F85542322A0796
    0199C13CC0220A9BC729EF2ECA638CFE'
]
~~~~~~~~~~~

The CBOR encoding (CBOR sequence) of the CBOR certificate is 138 bytes.

~~~~~~~~~~~
004301F50D2A6B5246432074657374204341442B044180442D54330046012345
6789AB36582102AE4CDB01F614DEFC7121285FDC7F5C6D1D42C95647F061BA00
80DF678867845E0558407F10A063DA8DB2FD49414440CDF85070AC22A266C7F1
DFB1577D9A35A295A8742E794258B76968C097F85542322A07960199C13CC022
0A9BC729EF2ECA638CFE
~~~~~~~~~~~

# X.509 Certificate Profile, ASN.1 {#appB}

EDITOR'S NOTE: The ASN.1 below is not up to date with the rest of the specification. The below ASN.1 for RFC 7925 profile should be in draft-ietf-uta-tls13-iot-profile instead.If CBOR Certificates support a large subset of RFC 5280, we should probably not duplicate all the ASN.1 in that document. Should be discussed what kind and how much (if any) ASN.1 this document needs. If possible, one option would be to have ASN.1 for the restrictions compared to RFC 5280.

~~~~~~~~~~~ ASN.1
IOTCertificate DEFINITIONS EXPLICIT TAGS ::= BEGIN

Certificate  ::= SEQUENCE {
  tbsCertificate        TBSCertificate,
  signatureAlgorithm    AlgorithmIdentifier,
  signatureValue        BIT STRING
}

TBSCertificate  ::= SEQUENCE {
  version           [0] INTEGER {v3(2)},
  serialNumber          INTEGER (1..MAX),
  signature             AlgorithmIdentifier,
  issuer                Name,
  validity              Validity,
  subject               Name,
  subjectPublicKeyInfo  SubjectPublicKeyInfo,
  extensions        [3] Extensions OPTIONAL
}

Name  ::= SEQUENCE SIZE (1) OF DistinguishedName

DistinguishedName  ::= SET SIZE (1) OF CommonName

CommonName  ::= SEQUENCE {
  type              OBJECT IDENTIFIER (id-at-commonName),
  value             UTF8String
}

Validity  ::= SEQUENCE {
  notBefore         UTCTime,
  notAfter          UTCTime
}

SubjectPublicKeyInfo  ::= SEQUENCE {
  algorithm         AlgorithmIdentifier,
  subjectPublicKey  BIT STRING
}

AlgorithmIdentifier  ::=  SEQUENCE  {
  algorithm         OBJECT IDENTIFIER,
  parameters        ANY DEFINED BY algorithm OPTIONAL  }
}

Extensions  ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::= SEQUENCE {
  extnId            OBJECT IDENTIFIER,
  critical          BOOLEAN DEFAULT FALSE,
  extnValue         OCTET STRING
 }

id-at-commonName    OBJECT IDENTIFIER   ::=
         {joint-iso-itu-t(2) ds(5) attributeType(4) 3}

END
~~~~~~~~~~~
