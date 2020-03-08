---
title: "CBOR Object Signing and Encryption (COSE): Headers for Carrying CBOR Compressed Certificates"
abbrev: CBOR Certificate Compression for COSE
docname: draft-mattsson-cose-cbor-cert-compress-latest

ipr: trust200902
cat: std
updates: draft-ietf-cose-x509

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: J. Preuss Mattsson
        name: John Preuss Mattsson
        org: Ericsson AB
        email: john.mattsson@ericsson.com
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        email: goran.selander@ericsson.com
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
        ins: M. Furuhed
        name: Martin Furuhed
        org: Nexus Group
        email: martin.furuhed@nexusgroup.com
        
normative:

  RFC2119:
  RFC7049:
  RFC7925:
  RFC8174:
  I-D.raza-ace-cbor-certificates:
  I-D.ietf-cbor-sequence:
  I-D.ietf-cose-x509:

informative:

  RFC8610:
  RFC7228:
  I-D.ietf-emu-eaptlscert:
  I-D.ietf-lake-reqs:

--- abstract

Certificate chains often take up the majority of the bytes transmitted in COSE message that carry certificates. Large messages can cause problems, particularly in constrained IoT environments. RFC 7925 defines a certificate profile for constrained IoT. General purpose compression algorithms can in many cases not compress RFC 7925 profiled certificates at all. By using the fact that the certificates are profiled, the CBOR certificate compression algorithms can in many cases compress RFC 7925 profiled certificates with over 50%. This document specifies the CBOR certificate compression algorithm for use with COSE.

--- middle

# Introduction

{{I-D.ietf-cose-x509}} provides attributes that refer to or contain X.509 certificates. X.509 certificates  often take up the majority of the bytes transmitted in COSE messages that carry certificates. Large messages negatively affect latency, but can also result in that the security protocol cannot be completed {{I-D.ietf-emu-eaptlscert}}. 

Large messages is particularly a problem for constrained IoT environments {{RFC7228}} {{I-D.ietf-lake-reqs}}. {{RFC7925}} defines a X.509 certificate profile for constrained IoT. The certificate profile in {{RFC7925}} is defined for TLS/DTLS 1.2 but works well also for COSE and other protocols. For such RFC 7925 profiled IoT certificates, general purpose compression algorithms can in many cases only provide negliable or no compression at all. {{I-D.raza-ace-cbor-certificates}} therefore defines a CBOR {{RFC7049}} compression algorithm for RFC 7925 profiled certificates. The algorithm works for all RFC 7925 profiled certificates and provide significant reduction in size, in many cases over 50%.

This document specifies the CBOR certificate compression algorithm {{I-D.raza-ace-cbor-certificates}} for use with COSE.

# Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# CBOR Certificate Compression Algorithm

This document specifies the CBOR certificate compression algorithm specified in Section 3 of {{I-D.raza-ace-cbor-certificates}} for use with COSE.

The CBOR Certificate compression algorithm takes as input an RFC 7925 profiled X.509 certificate. The output of the CBOR compression algorithm is a CBOR Sequence {{I-D.ietf-cbor-sequence}}, i.e. a sequence of concatenated CBOR encoded CBOR data items {{RFC7049}}. Compressed certificates can be analysed with any CBOR decoder and be validated against the CDDL specification defined in Section 3 of {{I-D.raza-ace-cbor-certificates}}.

The algorithm works for all RFC 7925 profiled certificates and provide significant reduction in size, in many cases over 50%. An example compression of a RFC 7925 profiled certificate is given below. See Appendix A of {{I-D.raza-ace-cbor-certificates}} for details.

~~~~~~~~~~~
+------------------+--------------+------------+--------------------+
|                  |   RFC 7925   |    zlib    |  CBOR Certificate  |
+------------------+---------------------------+--------------------+
| Certificate Size |     314      |     295    |         136        |
+------------------+--------------+------------+--------------------+
~~~~~~~~~~~

The header attributes defined in this document are:

CBORchain:
: This header attribute contains an ordered array of certicates similar to x5chain {{I-D.ietf-cose-x509}}. The difference being that all the included certificates are CBOR certificates {{I-D.raza-ace-cbor-certificates}} instead of DER encoded X.509 certificates. 

~~~~~~~~~~~
+-----------+-------+----------------+---------------------+
| Name      | Label | Value Type     | Description         |
+===========+=======+================+=====================+
| CBORchain | TBD1  | COSE_CBOR_Cert | An ordered chain of |
|           |       |                | CBOR certificates   |
+-----------+-------+----------------+---------------------+
~~~~~~~~~~~

Below is an equivalent CDDL [RFC8610] description of the text above.

~~~~~~~~~~~
COSE_CBOR_Cert = bstr / [ 2*certs: bstr ]
~~~~~~~~~~~


# Security Considerations

The security considerations in {{I-D.ietf-cose-x509}} and {{I-D.raza-ace-cbor-certificates}} apply.

# IANA Considerations

This document registers the COSE Header items in Table 1 in the "COSE Header Parameters" registry under the "CBOR Object Signing and Encryption (COSE)" heading. For each item, the 'Reference' field points to this document.
 
--- back

# Acknowledgments
{: numbered="no"}

The authors want to thank TBD for their valuable comments and feedback.

--- fluff
