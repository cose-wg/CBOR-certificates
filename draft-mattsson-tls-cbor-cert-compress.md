---
title: CBOR Certificate Algorithm for TLS Certificate Compression
abbrev: CBOR Certificate Compression for TLS
docname: draft-mattsson-tls-cbor-cert-compress-latest

ipr: trust200902
cat: std
updates: draft-ietf-tls-certificate-compression

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
  RFC7925:
  RFC8174:
  RFC8446:
  I-D.ietf-tls-dtls13:
  I-D.ietf-cbor-7049bis:
  I-D.ietf-tls-certificate-compression:
  I-D.raza-ace-cbor-certificates:
  I-D.ietf-cbor-sequence:

informative:

  RFC8610:
  RFC7228:
  I-D.ietf-emu-eaptlscert:
  I-D.ietf-lake-reqs:

--- abstract

Certificate chains often take up the majority of the bytes transmitted in TLS handshakes. Large handshakes can cause problems, particularly in constrained IoT environments. RFC 7925 defines a TLS certificate profile for constrained IoT. General purpose compression algorithms can in many cases not compress RFC 7925 profiled certificates at all. By using the fact that the certificates are profiled, the CBOR certificate compression algorithms can in many cases compress RFC 7925 profiled certificates with over 50%. This document specifies the CBOR certificate compression algorithm for use with TLS Certificate Compression in TLS 1.3 and DTLS 1.3.

--- middle

# Introduction

As stated in {{I-D.ietf-tls-certificate-compression}}, certificate chains often take up the majority of the bytes transmitted in TLS handshakes. Large handshakes negatively affect latency, but can also result in that the handshake cannot be completed {{I-D.ietf-emu-eaptlscert}}. To reduce handshake sizes, {{I-D.ietf-tls-certificate-compression}} specifies a mechanism for lossless compression of certificate chains in TLS 1.3 and defines three general purpose compression algorithms.

Large handshakes is particularly a problem for constrained IoT environments {{RFC7228}} {{I-D.ietf-lake-reqs}}. {{RFC7925}} defines a X.509 certificate profile for constrained IoT. The certificate profile in {{RFC7925}} is defined for TLS/DTLS 1.2 but works also for TLS 1.3 {{RFC8446}} and DTLS 1.3 {{I-D.ietf-tls-dtls13}}. For such profiled IoT certificates, general purpose compression algorithms such as zlib are however far from optimal and the general purpose compression algorithms defined in {{I-D.ietf-tls-certificate-compression}} can in many cases not compress RFC 7925 profiled certificates at all. {{I-D.raza-ace-cbor-certificates}} therefore defines a CBOR {{I-D.ietf-cbor-7049bis}} compression algorithm for RFC 7925 profiled certificates. The algorithm works for all RFC 7925 profiled certificates and provide significant reduction in size, in many cases over 50%.

This document specifies the CBOR certificate compression algorithm {{I-D.raza-ace-cbor-certificates}} for use with TLS Certificate Compression {{I-D.ietf-tls-certificate-compression}}. TLS Certificate Compression
can be used in TLS 1.3 {{RFC8446}} and DTLS 1.3 {{I-D.ietf-tls-dtls13}}.

# Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# CBOR Certificate Compression Algorithm

This document specifies the CBOR certificate compression algorithm specified in Section 3 of {{I-D.raza-ace-cbor-certificates}} for use with TLS Certificate Compression {{I-D.ietf-tls-certificate-compression}}. TLS Certificate Compression
can be used in TLS 1.3 {{RFC8446}} and DTLS 1.3 {{I-D.ietf-tls-dtls13}}. 

The CBOR Certificate compression algorithm takes as input a RFC 7925 profiled X.509 certificate. The output of the CBOR compression algorithm is a CBOR Sequence {{I-D.ietf-cbor-sequence}}, i.e. a sequence of concatenated CBOR encoded CBOR data items {{I-D.ietf-cbor-7049bis}}. Compressed certificates can be analysed with any CBOR decoder and be validated against the CDDL specification defined in Section 3 of {{I-D.raza-ace-cbor-certificates}}.

The algorithm works for all RFC 7925 profiled certificates and provide significant reduction in size, in many cases over 50%. An example compression of a RFC 7925 profiled certificate is given below.

~~~~~~~~~~~
+------------------+--------------+------------+--------------------+
|                  |   RFC 7925   |    zlib    |  CBOR Certificate  |
+------------------+---------------------------+--------------------+
| Certificate Size |     314      |     295    |         136        |
+------------------+--------------+------------+--------------------+
~~~~~~~~~~~


# Security Considerations

The security considerations in {{I-D.ietf-tls-certificate-compression}} and {{I-D.raza-ace-cbor-certificates}} apply.

# IANA Considerations

This document registers the following entry in the "Certificate Compression Algorithm IDs" registry under the "Transport Layer Security (TLS) Extensions" heading.

~~~~~~~~~~~
+------------------+------------------------------+-----------------+
| Algorithm Number | Description                  | Reference       |
+------------------+------------------------------+-----------------+
| TBD              | CBOR Certificate             | [this document] |
+------------------+------------------------------+-----------------+
~~~~~~~~~~~

--- back

# Acknowledgments
{: numbered="no"}

The authors want to thank TBD for their valuable comments and feedback.

--- fluff
