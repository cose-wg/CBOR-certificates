---
title: CBOR Profile of X.509 Certificates
# abbrev: CBOR-Certificates
docname: draft-raza-ace-cbor-certificates-latest

ipr: trust200902
wg: ACE Working Group
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
        name: John Mattsson
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
  RFC8174:
  RFC8610:
  I-D.ietf-cbor-sequence:
  I-D.ietf-tls-certificate-compression:

informative:
  RFC6347:
  RFC7228:
  RFC7925:
  RFC8446:
  RFC8613:
  I-D.ietf-tls-dtls13:
  I-D.selander-ace-cose-ecdhe:

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

  PointCompression:
    target: https://doi.org/10.1007/3-540-39799-X_31
    title: Use of Elliptic Curves in Cryptography.
    seriesinfo:
      "Springer, Cham.": "Lecture Notes of the Institute for Computer Sciences, Social Informatics and Telecommunications Engineering, vol 218."
    author:
      -
        ins: V.S. Miller
    date: 1986

--- abstract

This document specifies a CBOR encoding and profiling of X.509 public key certificate suitable for Internet of Things (IoT) deployments. The full X.509 public key certificate format and commonly used ASN.1 encoding is overly verbose for constrained IoT environments. Profiling together with CBOR encoding reduces the certificate size significantly with associated known performance benefits.

The CBOR certificates are compatible with the existing X.509 standard, enabling the use of profiled and compressed X.509 certificates without modifications in the existing X.509 standard.

--- middle

# Introduction  {#intro}

One of the challenges with deploying a Public Key Infrastructure (PKI) for the Internet of Things (IoT) is the size and encoding of X.509 public key certificates {{RFC5280}}, since those are not optimized for constrained environments {{RFC7228}}. More compact certificate representations are desirable. Due to the current PKI usage of X.509 certificates, keeping X.509 compatibility is necessary at least for a transition period. However, the use of a more compact encoding with the Concise Binary Object Representation (CBOR) {{RFC7049}} reduces the certificate size significantly which has known performance benefits in terms of decreased communication overhead, power consumption, latency, storage, etc.

CBOR is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g. encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. The Concise Data Definition Language (CDDL) {{RFC8610}} provides a way to express structures for protocol messages and APIs that use CBOR. {{RFC8610}} also extends the diagnostic notation.

CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme, where the three highest order bits of the initial byte contain information about the major type. CBOR supports several different types of data items, in addition to integers (int, uint), simple values (e.g. null), byte strings (bstr), and text strings (tstr), CBOR also supports arrays [] of data items, maps {} of pairs of data items, and sequences of data items. For a complete specification and examples, see {{RFC7049}}, {{RFC8610}}, and  {{I-D.ietf-cbor-sequence}}.

This document specifies the CBOR certificate profile, which is a CBOR based encoding and compression of the X.509 certificate format. The profile is based on previous work on profiling of X.509 certificates for Internet of Things deployments {{RFC7925}} {{X.509-IoT}} which retains backwards compatibility with X.509, and can be applied for lightweight certificate based authentication with e.g. TLS {{RFC8446}}, DTLS {{I-D.ietf-tls-dtls13}}, or EDHOC {{I-D.selander-ace-cose-ecdhe}}. The same profile can be used for "native" CBOR encoded certificates, which further optimizes the performance in constrained environments but are not backwards compatible with X.509, see {{native-CBOR}}.

Other work has looked at reducing size of X.509 certificates. The purpose of this document is to stimulate a discussion on CBOR based certificates. Further optimizations of this profile are known and will be included in future versions.

# Terminology   {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

This specification makes use of the terminology in {{RFC7228}}.

# CBOR Encoding {#encoding}

This section specifies the CBOR certificates. They can be of native type, in which case the signature is calculated on the cbor encoded data, or of compressed type, which is the outcome of CBOR encoding and lossless compression of X.509 certificates. In both cases the certificate content is adhering to the restrictions given by {{RFC7925}}, with the additional constraint that the subject is restricted to use the Common Name field as identifier. 

The corresponding ASN.1 schema is given in {{appA}}.

The encoding and compression has several components including: ASN.1 and base64 encoding is replaced with CBOR encoding, static fields are elided, and compression of elliptic curve points. The field encodings and associated savings compared with ASN1.1 encoding are listed below. Combining these different components reduces the certificate size significantly, see {{fig-table}}.

* Version number. The version number field is known (fixed to 3), and is omitted in the encoding.

* Serial number. The serial number is encoded as byte string. 

* Signature algorithm. If the signature algorithm is the default (ecdsa-with-SHA256) it is omitted in the encoding, otherwise encoded as a int identifier (see {{iana}}). 

* Issuer. In the general case, the Distinguished Name is encoded as CBOR map, but if only CN is present the value can be encoded as a single text value.

* Validity. The time is encoded as UnixTime in unsigned integer format. The validity is represented with one integer for the 'not before' time, and one for 'not after'. The 'not after' field can be null, representing a certificate without expiry date.

* Subject. The subject field is restricted to specifying the value of the common name. By RFC7925 an IoT subject is identified by either an EUI-64 for clients, or by a FQDN for servers. A EUI-64 is based on a 48bit unique MAC id. This is encoded as a CBOR byte string of length 6. For devices identified with a FQDN, a cbor text string is used.

* Subject public key info. If the algorithm identifier is the default (prime256v1), it is omitted, otherwise encoded as a int identifier (see {{iana}}). For the allowed ECC type keys, one of the public key ECC curve point elements can be calculated from the other, hence only one of the curve points is needed (point compression, see {{PointCompression}}).

* Extensions. The OIDs for the X.509 extensions mandated by rfc7925 always start with 2.5.29, hence only the trailing integer is needed to be encoded. (The extensions mandated to be supported by rfc7925 are encoded as 15, 19, 37 and 17.)

* Certificate signature algorithm. This algorithm field is always the same as the above signature algorithm, and is omitted in the encoding.

* Signature value. Since the signature algorithm and resulting signature length are known, padding and extra length fields which are present in the ASN.1 encoding are omitted. 

In addition to the above listed fields present in X.509, the cbor encoding introduces an additional type-field (single int) to indicate if the certificate is native cbor, or a compressed X.509 certificate.

~~~~~~~~~~~ CDDL
certificate = (
   type : int,
   serial_number : bytes,
   issuer : { + int => bytes } / text,
   validity_notBefore: uint,
   validity_notAfter: uint / null,
   subject : text / bytes
   public_key : bytes
   extensions : { * int => bytes },
   signature : bytes,
   ? ( signature_alg : int, public_key_info : int )
)
~~~~~~~~~~~

# Deployment settings {#dep-set}

CBOR certificates can be deployed with legacy X.509 certificates and CA infrastructure. In order to verify the signature, the CBOR certificate is used to recreate the original X.509 data structure to be able to verify the signature.

For the currently used DTLS v1.2 protocol, where the handshake is sent unencrypted, the actual encoding and compression can be done at different locations depending on the deployment setting. For example, the mapping between CBOR certificate and standard X.509 certificate can take place in a 6LoWPAN border gateway which allows the server side to stay unmodified. This case gives the advantage of the low overhead of a CBOR certificate over a constrained wireless links. The conversion to X.509 within an IoT device will incur a computational overhead, however, this is negligible compared to the reduced communication overhead.

For the setting with constrained server and server-only authentication, the server only needs to be provisioned with the CBOR certificate and does not perform the conversion to X.509. This option is viable when client authentication can be asserted by other means.

For DTLS v1.3, because certificates are encrypted, the proposed encoding needs to be done fully end-to-end, through adding the encoding/decoding functionality to the server. This corresponds to the proposed native mode, a new certificate compression scheme. The required changes on the server side are in line with recent protocols utilizing cbor encoding for communication with resource constrained devices {{RFC8613}}.


# Expected Certificate Sizes

The profiling size saving mainly comes from enforcing removal of issuer and subject info fields besides the common name. The encoding savings are presented above in {{encoding}}, for a sample certificate given in {{appC}} resulting in the numbers shown in {{fig-table}}.

After profiling, all duplicated information has been removed, and remaining text strings are minimal in size. Therefore no further size reduction can be reached with general compression mechanisms. (In practice the size might even grow slightly due to the compression encoding information, as illustrated in the table below.)

~~~~~~~~~~~

+-----------------------------------------------------------------+
|                   | X.509 Profiled | CBOR Encoded |    Zlib     |
+-----------------------------------------------------------------+
| Certificate Size  |      313       |     144      |     319     |
+-----------------------------------------------------------------+

~~~~~~~~~~~
{: #fig-table title="Comparing Sizes of Certificates (bytes)"}
{: artwork-align="center"}

# Native CBOR Certificates {#native-CBOR}

Further performance improvements can be achieved with the use of native CBOR certificates. In this case the signature is calculated over the CBOR encoded structure rather than the ASN.1 encoded structure. This removes entirely the need for ASN.1 and reduces the processing in the authenticating devices.

This solution applies when the devices are only required to authenticate with a set of native CBOR certificate compatible servers, which may become a preferred approach for future deployments. The mapping between X.509 and CBOR certificates enables a migration path between the backwards compatible format and the fully optimized format. This motivates introducing a type flag to indicate if the certificate should be restored to X.509 or kept cbor encoded.

# Security Considerations  {#sec-cons}

The CBOR profiling of X.509 certificates does not change the security assumptions needed when deploying standard X.509 certificates but decreases the number of fields transmitted, which reduces the risk for implementation errors.

Conversion between the certificate formats can be made in constant time to reduce risk of information leakage through side channels.

The current version of the format hardcodes the signature algorithm which does not allow for crypto agility. A COSE crypto algorithm can be specified with small overhead, and this changed is proposed for a future version of the draft.


# Privacy Considerations

The mechanism in this draft does not reveal any additional information compared to X.509.

Because of difference in size, it will be possible to detect that this profile is used.

The gateway solution described in {{dep-set}} requires unencrypted certificates.



# IANA Considerations  {#iana}


--- back

# Example CBOR encoding of DER encoded X.509 certificate {#appA}

TODO: Add DER encoded certificate and the corresponding CBOR compression.

~~~~~~~~~~~
(
  1,
  h'12826',
  "CA-id",
  1513715838,
  1593715838,
  h'0123456789AB',
  h'03E2145AF12D2509D6734A9D23F1F870F77E013C49E993669B03C9587599161F7D',
  {15: h'030205A0'},
h'8DADC9723AC8643DB5787A7E4D6B2B0D93046AF99B4E2FB768D44B229FF38EFE59E101DEFA25B01B60F74EB01C5F3B161850FFF042F56685497EADFFA7196C38'
)
~~~~~~~~~~~

# X.509 Certificate Profile, ASN.1 {#appB}

~~~~~~~~~~~ ASN.1
IOTCertificate DEFINITIONS EXPLICIT TAGS ::= BEGIN

Certificate  ::= SEQUENCE {
  tbsCertificate       TBSCertificate,
  signatureAlgorithm   SignatureIdentifier,
  signature            BIT STRING
}

TBSCertificate  ::= SEQUENCE {
  version       \[0\] INTEGER {v3(2)},
  serialNumber       INTEGER (1..MAX),
  signature       SignatureIdentifier,
  issuer       Name,
  validity       Validity,
  subject       Name,
  subjectPublicKeyInfo       SubjectPublicKeyInfo,
  extensions       \[3\] Extensions OPTIONAL
}

SignatureIdentifier ::= SEQUENCE {
  algorithm       OBJECT IDENTIFIER (ecdsa-with-SHA256)
Name  ::= SEQUENCE SIZE (1) OF DistinguishedName
DistinguishedName  ::= SET SIZE (1) OF CommonName
CommonName  ::= SEQUENCE {
  type       OBJECT IDENTIFIER (id-at-commonName),
  value       UTF8String
}

Validity  ::= SEQUENCE {
  notBefore       UTCTime,
  notAfter       UTCTime
}

SubjectPublicKeyInfo::= SEQUENCE {
  algorithm         AlgorithmIdentifier,
  subjectPublicKey          BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm        OBJECT IDENTIFIER (id-ecPublicKey),
  parameters       OBJECT IDENTIFIER (prime256v1)
}
  Extensions  ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::= SEQUENCE {
  extnId          OBJECT IDENTIFIER,
  critical        BOOLEAN DEFAULT FALSE,
  extnValue       OCTET STRING
 }

ansi-X9-62          OBJECT IDENTIFIER   ::=
         {iso(1) member-body(2) us(840) 10045}

id-ecPublicKey      OBJECT IDENTIFIER   ::=
         {ansi-X9-62 keyType(2) 1}

prime256v1          OBJECT IDENTIFIER   ::=
         {ansi-X9-62 curves(3) prime(1) 7}

ecdsa-with-SHA256   OBJECT IDENTIFIER   ::=
         {ansi-X9-62 signatures(4) ecdsa-with-SHA2(3) 2}

id-at-commonName    OBJECT IDENTIFIER   ::=
         {joint-iso-itu-t(2) ds(5) attributeType(4) 3}

END
~~~~~~~~~~~

# Certificate Example {#appC}

TODO: Remove or use in compression example as explanation for the X.509 byte string 0x83a4e73a.......

This section shows an example of an X.509 profiled certificate before CBOR encoding.

~~~~~~~~~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: DEC (HEX)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: <23 byte issuer ID>
        Validity
            Not Before: <not_before_ts>
            Not After : <not_after_ts>
        Subject: <23 byte UID>
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    .. .. ..
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature, Key Encipherment
    Signature Algorithm: ecdsa-with-SHA256
         .. .. ...
~~~~~~~~~~~
