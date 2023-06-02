---
title: "CBOR Encoded Certificate Revocation Management"
docname: draft-ietf-cose-cbor-cert-revocation-latest
abbrev: C509 Revocation

ipr: trust200902
cat: std

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2
venue:
  group: "CBOR Object Signing and Encryption"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "cose-wg/CBOR-certificates"

author:
      -
        ins: J. Preuß Mattsson
        name: John Preuß Mattsson
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

  RFC5280
  RFC6960
  RFC8949
  ToBeRepopulated

informative:

  ToBeRepopulated

--- abstract

This document specifies CBOR encodings of messages for certificate revocation lists, and 

--- middle

# Introduction {#intro}

TODO

# Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

This specification makes use of the terminology in {{RFC5280}}, and {{RFC6960}}. When referring to CBOR, this specification always refers to Deterministically Encoded CBOR as specified in Sections 4.2.1 and 4.2.2 of {{RFC8949}}.

# C509 Certificate Revocation List {#CRL}

The section defines the C509 Certificate Revocation List (CRL) format based on and compatible with {{RFC5280}} reusing the formatting for C509 certificates defined in {{certificate}}.

~~~~~~~~~~~ CDDL
C509CertificateRevocationList = [
   TBSCertificateRevocationList,
   issuerSignatureValue : any,
]

; The elements of the following group are used in a CBOR Sequence:
TBSCertificateSigningRequest = (
   C509CertificateRevocationListType: int,
   issuer: Name,
   thisUpdate: Time,
   nextUpdate: Time,
   revokedCertificates: RevokedCertificates,
   crlExtensions: Extensions,
   issuerSignatureAlgorithm: AlgorithmIdentifier,
)

RevokedCertificates = [
    userCertificate: CertificateSerialNumber,
    revocationDate: Time,
    crlEntryExtensions: Extensions,
]
~~~~~~~~~~~
{: #fig-C509CRLCDDL title="CDDL for C509CertificateRevocationList."}
{: artwork-align="center"}

# C509 Online Certificate Status Protocol {#OCSP}

## C509 OCSP request

To encode OCSP requests, the CDDL below gives the cbor encoding corresponding to the ASN.1 encoding defined in RFC 6960 {{RFC6960}}.

~~~~~~~~~~~ CDDL
 C509OCSPRequest    =     [
       TBSRequest,
       optionalSignature : *any, 
 ]

   TBSRequest   =     [
       version : uint .default 1,
       requestorName : *GeneralName,
       requestList : [+Request],
       requestExtensions : *[+extension]
   ]

   Request    =    [
       reqCert : CertID,
       singleRequestExtensions : *[+extension]
   ]

   CertID          =     [
       hashAlgorithm : AlgorithmIdentifier,
       issuerNameHash : bytes, -- Hash of issuer's DN
       issuerKeyHash : bytes, -- Hash of issuer's public key
       serialNumber : CertificateSerialNumber 
   ]

   extension = TBD

   IMPORTS
	GeneralName, AlgorithmIdentifier, CertificateSerialNumber
   FROM	
	Main C509 document
~~~~~~~~~~~
{: #fig-C509OCSPREQCDDL title="CDDL for C509OCSPRequest."}
{: artwork-align="center"}

## C509 OCSP response

Concerning OCSP responses we address the id-pkix-ocsp-basic response type as defined in defined in RFC 6960 {{RFC6960}}.

~~~~~~~~~~~ CDDL
   C509OCSPResponse = [
      responseStatus : C509OCSPResponseStatus,
      responseBytes : *BasicOCSPResponse
  ]

   OCSPResponseStatus = 0..6 ; inclusive range
	; semantics of integer values as in rfc6960, 4.2.1.  ASN.1 Specification of the OCSP Response

   BasicOCSPResponse    =  [
      tbsResponseData : ResponseData,
      signatureAlgorithm : AlgorithmIdentifier,
      signature : any,
      certs : *[C509Certificate]
   ]
   
   ResponseData = [
      version : uint .default 1,
      responderID : ResponderID,
      producedAt : Time,
      responses : [+SingleResponse],
      responseExtensions : *[+extension]

   ResponderID = Name / KeyHash

   Name = TBD

   KeyHash = bytes -- SHA-1 hash of responder's public key (excluding the tag and length fields)
	; OBSOLETE, but needed if we want to fully recreate RFC6960 style messages

   SingleResponse = [
      certID : CertID,
      certStatus : CertStatus,
      thisUpdate : Time,
      nextUpdate : *Time,
      singleExtensions : *[+extension]
   ]

   CertStatus = {1: NULL} / {2: RevokedInfo} / {3: NULL}
	; good / revoked / unknown, semantics from RFC6960 

   RevokedInfo = (
       revocationTime : Time,
       revocationReason : *CRLReason 
   )
   
   CRLReason = 0..10 ; inclusive range
	; semantics of integer values from RFC6960, 5.3.1.
~~~~~~~~~~~
{: #fig-C509OCSPRESCDDL title="CDDL for C509OCSPResponse."}
{: artwork-align="center"}

# Example C509 CRL Message {#appA}
TODO

# Example C509 OCSP Message {#appB}
TODO

# Acknowledgments
{: numbered="no"}

TODO
