// DER encoded X.509 to CBOR encoded X.509 (C509)
// Copyright (c) 2021--2024, Ericsson and John Preuß Mattsson <john.mattsson@ericsson.com> + RISE and Joel Höglund <joel.hoglund@ri.se>
// This version implements a critical subset of draft-ietf-cose-cbor-encoded-cert-09
//
// To read a DER encoded X.509 from file:
// "cargo r f <der encoded certificate>"
// -- A few sample certificates are present in ../certs
//
// To read a DER encoded X.509 chain/bag from a TLS server:
// "cargo r u www.ietf.org"
// "cargo r u tools.ietf.org"
//
// http://cbor.me/ is recommended to transform beteen CBOR encoding and diagniostic notatation.
// https://lapo.it/asn1js/ decodes DER encoded ASN.1
// https://misc.daniel-marschall.de/asn.1/oid-converter/online.php transforms between OID dot notation and DER
//
// This software may be distributed under the terms of the 3-Clause BSD License.
//
// Minimal update history & limitations
//
// Version 0.3 of the code released in March 2024
// A combination of a bugfix version and changes which have been made between draft-02 and draft-09
//
// Please note: while this version contains integer encodings for all the extension names listed in the
// C509 Extensions Registry, not all extension values are fully cbor encoded. In those cases a warning is
// given during the encoding.
// 
// Version 0.2 of the code was never added to the github repo, but has been uploaded as an archive for 
// completeness
// 
// Version 0.1 of the code released 2021-05-25, roughly corresponding to draft-02
//
// Miscellaneous
//
// The software uses the non default crate bit_reverse
//
// The software currently give warnings for "non-supported" options
// "cargo r u misc.daniel-marschall.de" (ext id-pe-tlsfeature)
// "cargo r u www.cisco.com" (IPsec EKUs)
// "cargo r u www.microsoft.com" (extensions)
//
use crate::cbor::*;
use crate::der::*;
use crate::help::*;
use bit_reverse::LookupReverse;
//use hex::FromHex; //used for testing
use std::env;
//use std::process;  //used for testing
use {rustls::*, std::io::Write, webpki, webpki_roots};
use {std::env::args, std::str::from_utf8};
//use log::{debug, error, log_enabled, info, Level};

pub const SECG_EVEN: u8 = 0x02;
pub const SECG_ODD: u8 = 0x03;
pub const SECG_UNCOMPRESSED: u8 = 0x04;
pub const SECG_EVEN_COMPRESSED: u8 = 0xfe;
pub const SECG_ODD_COMPRESSED: u8 = 0xfd;
struct Cert {
  der: Vec<u8>,
  cbor: Vec<Vec<u8>>,
}
pub const PRINT_INPUT: bool = false;
pub const PRINT_OUTPUT: bool = false;
pub const PRINT_COSE: bool = true;
pub const PRINT_TLS: bool = false;
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
fn main() {
  env::set_var("RUST_BACKTRACE", "1");
  //env_logger::init();
  // get a single certificate from file or a chain/bag from a tls server and parse them
  let first_arg = args().nth(1).expect("No option given!");
  let second_arg = args().nth(2).expect("No file/domain name given!");
  let certs = match &first_arg[..] {
      "f" => vec![parse_x509_cert(std::fs::read(second_arg).expect("No such file!"))],
      "u" => get_certs_from_tls(second_arg),
      _ => panic!("expected f or u"),
  };
  print_information(&certs);
}
/******************************************************************************************************/
/******************************************************************************************************/
// make a TLS connection to get server certificate chain/bag
fn get_certs_from_tls(domain_name: String) -> Vec<Cert> {
  let mut config = rustls::ClientConfig::new();
  config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
  let dns_name = webpki::DNSNameRef::try_from_ascii_str(&domain_name).unwrap();
  let mut sess = rustls::ClientSession::new(&std::sync::Arc::new(config), dns_name);
  let mut sock = std::net::TcpStream::connect(domain_name + ":443").unwrap();
  let mut tls = rustls::Stream::new(&mut sess, &mut sock);
  tls.write_all(b"GET / HTTP/1.1").unwrap();
  tls.flush().unwrap();
  tls.sess.get_peer_certificates().unwrap().iter().map(|c| parse_x509_cert(c.0.clone())).collect()
}
/******************************************************************************************************/
/******************************************************************************************************/
// Parse a DER encoded X509 and encode it as C509
fn parse_x509_cert(input: Vec<u8>) -> Cert {
  
  let mut output = Vec::new();
  // der Certificate
  let certificate = der_vec_len(&input, ASN1_SEQ, 3);
  let tbs_certificate = der_vec_len(certificate[0], ASN1_SEQ, 8);
  let version = der(tbs_certificate[0], 0xa0);
  let serial_number = der_uint(tbs_certificate[1]);
  let signature = tbs_certificate[2];
  let issuer = tbs_certificate[3];
  let validity = der_vec_len(tbs_certificate[4], ASN1_SEQ, 2);
  let not_before = validity[0];
  let not_after = validity[1];
  let subject = tbs_certificate[5];
  let subject_public_key_info = der_vec_len(tbs_certificate[6], ASN1_SEQ, 2);
  let spki_algorithm = subject_public_key_info[0]; //TODO, update?
  let subject_public_key = der(subject_public_key_info[1], ASN1_BIT_STR);
  let extensions = der_vec(der(tbs_certificate[7], 0xa3), ASN1_SEQ); //0xa3 = [3] EXPLICIT, mandatory start of ext.seq if present
  let signature_algorithm = certificate[1];
  let signature_value = der(certificate[2], ASN1_BIT_STR);
  // version
  assert!(der(version, ASN1_INT)[0] == 2, "Expected v3!");
  output.push(cbor_uint(1));
  // serial_number
  output.push(cbor_bytes(serial_number));
  // signature
  assert!(signature_algorithm == signature, "Expected signature_algorithm == signature!");
  // issuer
  output.push(cbor_name(issuer));
  // validity
  output.push(cbor_time(not_before));
  output.push(cbor_time(not_after));
  // subject
  output.push(cbor_name(subject));
 
  // subjectPublicKeyInfo
  assert!(subject_public_key[0] == 0, "expected 0 unused bits");
  let subject_public_key = &subject_public_key[1..];
  if let Some(pk_type) = pk_map(spki_algorithm) {
      output.push(cbor_int(pk_type));
      // Special handling for RSA
      if pk_type == PK_RSA_ENC {
          let rsa_pk = der_vec_len(subject_public_key, ASN1_SEQ, 2);
          let n = cbor_bytes(der_uint(rsa_pk[0]));
          let e = cbor_bytes(der_uint(rsa_pk[1]));
          if e == [0x43, 0x01, 0x00, 0x01] {
              output.push(n);
          } else {
              output.push(cbor_array(&[n, e]));
          }
      // Special handling for ECDSA
      /*
      Please note: 
      
      For elliptic curve public keys in Weierstraß form (id-ecPublicKey), keys may be point compressed
      as defined in Section 2.3.3 of [SECG]. Native C509 certificates with Weierstraß form keys use the
      octets 0x02, 0x03, and 0x04 as defined in [SECG]. If a DER encoded certificate with a uncompressed
      public key of type id-ecPublicKey is CBOR encoded with point compression, the octets 0xfe and 0xfd
      are used instead of 0x02 and 0x03 in the CBOR encoding to represent even and odd y-coordinate,
      respectively.
      */
      } else if [PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_BRAINPOOL256R1, PK_BRAINPOOL384R1, PK_BRAINPOOL512R1, PK_FRP256V1].contains(&pk_type) {
          assert!(subject_public_key.len() % 2 == 1, "Expected odd subject public key length!");
          let coord_size = (subject_public_key.len() - 1) / 2;
          let secg_byte = subject_public_key[0];
          let x = &subject_public_key[1..1 + coord_size];
          if secg_byte == SECG_UNCOMPRESSED {
              let y = &subject_public_key[1 + coord_size..];
              if y[coord_size - 1] & 1 == 0 {
                  output.push(cbor_bytes(&[&[SECG_EVEN_COMPRESSED], x].concat()));
              } else {
                  output.push(cbor_bytes(&[&[SECG_ODD_COMPRESSED], x].concat()));
              }
          } else if secg_byte == SECG_EVEN || secg_byte == SECG_ODD as u8 {
              output.push(cbor_bytes(&[&[-(secg_byte as i8) as u8], x].concat()));
          } else {
              panic!("Expected SECG byte to be 2, 3, or 4!")
          }
      } else {
          output.push(cbor_bytes(subject_public_key));
      }
  } else {
      let oid = der(der_vec(spki_algorithm, ASN1_SEQ)[0], ASN1_OID);
      print_warning("No C509 int registered for public key algorithm identifier, oid", &spki_algorithm, oid);
      output.push(cbor_alg_id(spki_algorithm));
      output.push(cbor_bytes(subject_public_key));
  }
  // issuerUniqueID, subjectUniqueID -- not supported
  // extensions
  let mut vec = Vec::new();
  for e in &extensions {
      let extension = der_vec(e, ASN1_SEQ);
      assert!(extension.len() < 4, "Expected length 2 or 3");
      let oid = der(extension[0], ASN1_OID);
      let mut crit_sign = 1;
      if extension.len() == 3 {
          assert!(der(extension[1], ASN1_BOOL) == [0xff], "Expected critical == true");
          crit_sign = -1;
      }
      let extn_value = der(extension[extension.len() - 1], ASN1_OCTET_STR);
      if let Some(ext_type) = ext_map(oid) {
          //println!("Working on {}. extensions.len() = {}, crit status: {:?}", ext_type, extensions.len(), cbor_int(crit_sign * ext_type as i64));
          //Note: We need look-ahead for the keyUsage only case and surpress the crit.sign, as it will be respresented by a negative keyUsage value only
          if extensions.len() == 1 && ext_type == EXT_KEY_USAGE {
              vec.push(cbor_int(ext_type as i64));
          } else {
              vec.push(cbor_int(crit_sign * ext_type as i64));
          }
          vec.push(match ext_type {
              EXT_SUBJECT_KEY_ID => cbor_bytes(der(extn_value, ASN1_OCTET_STR)),
              EXT_KEY_USAGE => cbor_ext_key_use(extn_value, crit_sign * extensions.len() as i64),
              EXT_SUBJECT_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
              EXT_BASIC_CONSTRAINTS => cbor_ext_bas_con(extn_value),
              EXT_CRL_DIST_POINTS => cbor_ext_crl_dist(extn_value),
              EXT_CERT_POLICIES => cbor_ext_cert_policies(extn_value),
              EXT_AUTH_KEY_ID => cbor_ext_auth_key_id(extn_value),
              EXT_EXT_KEY_USAGE => cbor_ext_eku(extn_value),
              EXT_AUTH_INFO => cbor_ext_info_access(extn_value),
              EXT_SCT_LIST => cbor_ext_sct(extn_value, not_before),
              EXT_SUBJECT_DIRECTORY_ATTR => {cbor_store_only(extn_value, extension[0], oid)}, //cbor_ext_directory_attr(extn_value), 
              EXT_ISSUER_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),     //Note: "Issuer Alternative Name (issuerAltName). extensionValue is encoded exactly like subjectAltName."
              EXT_NAME_CONSTRAINTS => {cbor_store_only(extn_value, extension[0], oid)},   //cbor_ext_name_constraints(extn_value),      //Sample certificates welcome
              EXT_POLICY_MAPPINGS => {cbor_store_only(extn_value, extension[0], oid)},    //cbor_ext_policy_mappings(extn_value),       //Sample certificates welcome
              EXT_POLICY_CONSTRAINTS => {cbor_store_only(extn_value, extension[0], oid)}, //cbor_ext_policy_constraints(extn_value),    //Sample certificates welcome
              EXT_FRESHEST_CRL => cbor_ext_crl_dist(extn_value),                              //Note: "Freshest CRL (freshestCRL). extensionValue is encoded exactly like cRLDistributionPoints"
              EXT_INHIBIT_ANYPOLICY => {cbor_store_only(extn_value, extension[0], oid)},  //cbor_ext_inhibit_anypolicy(extn_value),     //Sample certificates welcome
              EXT_SUBJECT_INFO_ACCESS => cbor_ext_info_access(extn_value),
              EXT_IP_RESOURCES => cbor_ext_ip_res(extn_value),
              EXT_AS_RESOURCES => cbor_ext_as_res(extn_value),
              EXT_IP_RESOURCES_V2 => cbor_ext_ip_res(extn_value),
              EXT_AS_RESOURCES_V2 => cbor_ext_as_res(extn_value),
              EXT_BIOMETRIC_INFO => cbor_bytes(extn_value),            //Store only
              EXT_PRECERT_SIGNING_CERT => cbor_bytes(extn_value),      //Store only
              EXT_OCSP_NO_CHECK => cbor_bytes(extn_value),             //Store only
              EXT_QUALIFIED_CERT_STATEMENTS => cbor_bytes(extn_value), //Store only
              EXT_S_MIME_CAPABILITIES => cbor_bytes(extn_value),       //Store only
              EXT_TLS_FEATURES => cbor_bytes(extn_value),              //Store only
              _ => panic!("Unexpected extension'"),
          });
      } else {
          print_warning("No C509 int registered for extension oid", extension[0], oid);
          vec.push(cbor_bytes(oid));
          if crit_sign == -1 {
              vec.push(cbor_simple(CBOR_TRUE));
          }
          vec.push(cbor_bytes(extn_value));
      }
  }
  /*
    Optimisation: if only a keyUsage field is present, skip the array for extensions.
    This requires the minus sign of the EXT_KEY_USAGE value (2) to be surpressed above
  */
  output.push(cbor_opt_array(&vec, EXT_KEY_USAGE as u8));
  // signatureAlgorithm, signatureValue
  assert!(signature_value[0] == 0, "expected 0 unused bits");
  let signature_value = &signature_value[1..];
  if let Some(sig_type) = sig_map(signature_algorithm) {
      output.push(cbor_int(sig_type));
      // Special handling for ECDSA
      if [SIG_ECDSA_SHA1, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_ECDSA_SHAKE128, SIG_ECDSA_SHAKE256].contains(&sig_type) {
          output.push(cbor_ecdsa(signature_value));
      } else {
          output.push(cbor_bytes(signature_value));
      }
  } else {
      let oid = der(der_vec(signature_algorithm, ASN1_SEQ)[0], ASN1_OID);
      print_warning("No C509 int regisered for signature algorithm identifier, oid", &signature_algorithm, oid);
      output.push(cbor_alg_id(signature_algorithm));
      output.push(cbor_bytes(signature_value));
  }
  Cert { der: input, cbor: output }
}
/******************************************************************************************************/
// CBOR encode a DER encoded Name field
fn cbor_name(b: &[u8]) -> Vec<u8> {
  let name = der_vec(b, ASN1_SEQ);
  let mut vec = Vec::new();
  for rdn in &name {
      let attributes = der_vec_len(rdn, ASN1_SET, 1);
      for item in attributes {
          let attribute = der_vec_len(item, ASN1_SEQ, 2);
          let oid = der(attribute[0], ASN1_OID);
          let der_value = attribute[1];
          if let Some(att_type) = att_map(oid) {
              if att_type == ATT_EMAIL || att_type == ATT_DOMAIN_COMPONENT {
                  vec.push(cbor_int(att_type as i64));
                  let att_value = der(der_value, ASN1_IA5_SRT);
                  vec.push(cbor_text(att_value));
              } else {
                  let (sign, att_value) = if der_value[0] == ASN1_PRINT_STR { (-1, der(der_value, ASN1_PRINT_STR)) } else { (1, der(der_value, ASN1_UTF8_STR)) };
                  vec.push(cbor_int(sign * att_type as i64));
                  vec.push(cbor_text(att_value));
              }
          } else {
              print_warning("No C509 int regisered for attribute oid", attribute[0], oid);
              vec.push(cbor_bytes(oid));
              vec.push(cbor_bytes(der_value));
          }
      }
  }
  
  /*
  
  If Name contains a single Attribute containing an utf8String encoded 'common name' it is encoded as follows:

  *If the text string has an even length {{{≥}}} 2 and contains only the symbols '0'–'9' or 'a'–'f',
   it is encoded as a CBOR byte string, prefixed with an initial byte set to '00'.
   
   *If the text string contains an EUI-64 of the form "HH-HH-HH-HH-HH-HH-HH-HH" where 'H' is one of
   the symbols '0'–'9' or 'A'–'F' it is encoded as a CBOR byte string prefixed with an initial byte set to
   '01', for a total length of 9. An EUI-64 mapped from a 48-bit MAC address (i.e., of the form
   "HH-HH-HH-FF-FE-HH-HH-HH) is encoded as a CBOR byte string prefixed with an initial byte set to '01',
   for a total length of 7.
   
   *Otherwise it is encoded as a CBOR text string.
   
  */
  let eui_64 = regex::Regex::new(r"^([A-F\d]{2}-){7}[A-F\d]{2}$").unwrap();
  let is_hex = regex::Regex::new(r"^(?:[A-Fa-f0-9]{2})*$").unwrap();
  
  if vec.len() == 2 && vec[0] == [ATT_COMMON_NAME as u8] {
      //let cn = from_utf8(&vec[0][1..]).unwrap();
      vec.remove(0);
      if eui_64.is_match(from_utf8(&vec[0][1..]).unwrap()) {
          vec[0].retain(|&x| x != b'-' && x != 0x77); // 0x77 = text string length 23
          if &vec[0][6..10] == b"FFFE" {
              vec[0].drain(6..10);
          }
          vec[0].insert(0, '1' as u8); 
          vec[0].insert(0, '0' as u8); 
          vec[0] = cbor_bytes(&hex::decode(&vec[0]).unwrap());
      } else if is_hex.is_match(from_utf8(&vec[0][1..]).unwrap()) {
        vec[0][0] = '0' as u8; //overwrite the added utf8 text marker at the start
        vec[0].insert(0, '0' as u8); 
        vec[0] = cbor_bytes(&hex::decode(&vec[0]).unwrap());
        
      }
      
      return vec[0].clone();
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encode a DER encoded Time field (ruturns ~biguint)
fn cbor_time(b: &[u8]) -> Vec<u8> {
  let time_string = if b[0] == ASN1_UTC_TIME as u8 { [b"20", der(b, ASN1_UTC_TIME)].concat() } else { der(b, ASN1_GEN_TIME).to_vec() };
  let time_string = from_utf8(&time_string).unwrap();
  match time_string {
      "99991231235959Z" => cbor_simple(CBOR_NULL),
      _ => cbor_uint(chrono::NaiveDateTime::parse_from_str(time_string, "%Y%m%d%H%M%SZ").unwrap().timestamp() as u64),
  }
}
// CBOR encode a DER encoded Algorithm Identifier
fn cbor_alg_id(b: &[u8]) -> Vec<u8> {
  let ai = der_vec(b, ASN1_SEQ);
  assert!(ai.len() < 3, "Expected length 1 or 2");
  let oid = cbor_bytes(der(ai[0], ASN1_OID));
  if ai.len() == 1 {
      oid
  } else {
      let par = cbor_bytes(ai[1]);
      cbor_array(&[oid, par])
  }
}
// CBOR encodes a DER encoded ECDSA signature value
fn cbor_ecdsa(b: &[u8]) -> Vec<u8> {
  let signature_seq = der_vec(b, ASN1_SEQ);
  let r = der_uint(signature_seq[0]).to_vec();
  let s = der_uint(signature_seq[1]).to_vec();
  let max = std::cmp::max(r.len(), s.len());
  cbor_bytes(&[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat())
}
fn cbor_opt_array(vec: &[Vec<u8>], t: u8) -> Vec<u8> {
  if vec.len() == 2 && vec[0] == [t] {
      vec[1].clone()
  } else {
      cbor_array(&vec)
  }
}
/******************************************************************************************************/
/*
Below is a list of encoding functions for the supported extensions listed in C509 Extensions Registry
*/

/*
  Placeholder function to store the raw extension value as bytes 
*/
fn cbor_store_only(b: &[u8], v: &[u8], oid: &[u8]) -> Vec<u8> {
  print_warning("Warning, currently storing raw data for extension with oid", v, oid);
  cbor_bytes(b)
}

/*
CBOR encode GeneralNames
Used for and in:
EXT_SUBJECT_ALT_NAME
Authority Key Identifier extension
Note: no wrapping array if content is a single name of type opt
*/
fn cbor_general_names(b: &[u8], t: u8, opt: u8) -> Vec<u8> {
  let unwrap = opt;
  let names = der_vec(b, t);
  let mut vec = Vec::new();
  for name in names {
      //println!("handling name: {:02x?}", name);
      let value = der(name, name[0]);
      let context_tag = name[0] as u64 & 0x0f;
      //ongoing: special handling of otherName:
      if context_tag == 0 {
          let inner_value = &value[12..]; //TODO, check handling of long values
          match value {
              [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, ..] => match value[9] {
                  0x0B => {
                      vec.push(cbor_int(-3));
                      vec.push(cbor_bytes(inner_value));
                  }
                  0x09 => {
                      vec.push(cbor_int(-2));
                      vec.push(cbor_other_name_mail(inner_value));
                  }
                  0x04 => {
                      vec.push(cbor_int(-1));
                      vec.push(cbor_other_name_hw(inner_value));
                  }
                  _ => { vec.push(cbor_int(0)); vec.push(cbor_other_name(value)) }, //resort to generic otherName encoding, [ ~oid, bytes ]
              },
              _ => { vec.push(cbor_int(0)); vec.push(cbor_other_name(value)) }, //same as above 
          }
      } else {
          vec.push(cbor_uint(context_tag));
          vec.push(match context_tag {
              1 => cbor_text(value),  // rfc822Name
              2 => cbor_text(value),  // dNSName
              4 => cbor_name(value),  // Name (TODO a4?)
              6 => cbor_text(value),  // uniformResourceIdentifier
              7 => cbor_bytes(value), // iPAddress
              8 => cbor_bytes(value), // registeredID : should be stored as ~oid
              _ => panic!("Unknown general name"),
          })
      }
  }
  cbor_opt_array(&vec, unwrap)
}
/******************************************************************************************************/
/*
CBOR encoding of the general otherName format
ASN.1 input description
-- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
-- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax
 AnotherName ::= SEQUENCE {
 type-id    OBJECT IDENTIFIER,
 value      [0] EXPLICIT ANY DEFINED BY type-id }
CDDL
[ ~oid, bytes ]
*/
fn cbor_other_name(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  let (oid_raw, rest) = der_split(b, false);
  let oid = der(oid_raw,ASN1_OID);
 
  let raw_value = der(rest,ASN1_INDEX_ZERO);
  //let (choice, value_raw) = der_split(rest, false);
  //Since the raw value can be of any type, we just store it as a byte string without parsing
 
  vec.push(cbor_bytes(oid));
  vec.push(cbor_bytes(raw_value));
  cbor_array(&vec)
}
/******************************************************************************************************/
/*
Notes on the OtherNames with special encodings:
***********************************
otherName with BundleEID
 ASN.1
ID: -3
1.3.6.1.5.5.7.8.11
06 08 2B 06 01 05 05 07 08 0B
Value: eid-structure from RFC 9171
https://www.rfc-editor.org/rfc/rfc9171.html
 Each BP endpoint ID (EID) SHALL be represented as a CBOR array comprising two items.
The first item of the array SHALL be the code number identifying the endpoint ID's URI scheme,
as defined in the registry of URI scheme code numbers for the Bundle Protocol. Each URI scheme
code number SHALL be represented as a CBOR unsigned integer.
The second item of the array SHALL be the applicable CBOR encoding of the scheme-specific part
of the EID, defined as noted in the references(s) for the URI scheme code number registry entry
for the EID's URI scheme.
eid-structure = [
uri-code: uint,
SSP: any
]
SSP: [
nodenum: uint,
servicenum: uint
]
https://www.rfc-editor.org/rfc/rfc9174.html
 This non-normative example demonstrates an otherName with a name form of
BundleEID to encode the node ID "dtn://example/".
The hexadecimal form of the DER encoding of the otherName is as follows:
a01c06082b0601050507080ba010160e64746e3a2f2f6578616d706c652f
And the text decoding in Figure 28 is an output of Peter Gutmann's "dumpasn1" program.
0  28: [0] {
2   8:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 8 11'
12  16:   [0] {
14  14:     IA5String 'dtn://example/'
     :     }
     :   }
*/
fn _cbor_other_name_bundle(b: &[u8]) -> Vec<u8> {
  /*
  TODO: agree on a possibly more fine grained parsing of the structure contained in the value.
  For now just store the content as a byte string
  let mut vec = Vec::new();
  let mut value;
  match b[0] {
   ASN1_IA5_SRT => { value = der(b, ASN1_IA5_SRT)
   },
   ASN1_UTF8_STR => { value = der(b, ASN1_UTF8_STR)
   },
   _ => panic!("Unknown general value type"),
  }
  */
  let mut vec = Vec::new();
  vec.push(cbor_bytes(b));
  cbor_array(&vec)
}
/*
otherName with SmtpUTF8Mailbox
ID -2
1.3.6.1.5.5.7.8.9
06 08 2B 06 01 05 05 07 08 09
https://www.rfc-editor.org/rfc/rfc8398.html
SmtpUTF8Mailbox ::= UTF8String (SIZE (1..MAX))
This non-normative example demonstrates using SmtpUTF8Mailbox as an
otherName in GeneralName to encode the email address
"u+8001u+5E2B@example.com".
The hexadecimal DER encoding of the email address is:
A022060A 2B060105 05070012 0809A014 0C12E880 81E5B8AB 40657861
6D706C65 2E636F6D
The text decoding is:
  0  34: [0] {
  2  10:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 0 18 8 9'
 14  20:   [0] {
 16  18:     UTF8String '..@example.com'
       :     }
       :   }
*WARNING* the OID in this example does not match the OID found in OID databases
*/
fn cbor_other_name_mail(b: &[u8]) -> Vec<u8> {
  // let mut vec = Vec::new();
  let value;
  value = der(b, ASN1_UTF8_STR);
  cbor_text(value)
  //cbor_array(&vec)
}
/*
otherName with hardwareModuleName
 Note: this is used in the DevID certificates
 ASN.1
 ID: -1
1.3.6.1.5.5.7.8.4
06 08 2B 06 01 05 05 07 08 04
Value: [ ~oid, bytes ]
https://www.rfc-editor.org/rfc/rfc4108.html
A HardwareModuleName is composed of an object identifier and an octet string:
HardwareModuleName ::= SEQUENCE {
hwType OBJECT IDENTIFIER,
hwSerialNum OCTET STRING }
*/
fn cbor_other_name_hw(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  let another_name_vec = der_vec(b, ASN1_SEQ);
  let type_id = der(another_name_vec[0], ASN1_OID);
  let value = der(another_name_vec[1], ASN1_OCTET_STR);
  vec.push(cbor_bytes(type_id));
  vec.push(cbor_bytes(value));
  cbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encodes a Autonomous System Identifier extension
ASN.1 input
 id-pe-autonomousSysIds  OBJECT IDENTIFIER ::= { id-pe 8 }
ASIdentifiers     ::= SEQUENCE
{
asnum             [0] EXPLICIT ASIdentifierChoice OPTIONAL,
rdi               [1] EXPLICIT ASIdentifierChoice OPTIONAL
}
ASIdentifierChoice  ::= CHOICE
{
inherit           NULL, -- inherit from issuer --
asIdsOrRanges     SEQUENCE OF ASIdOrRange
}
ASIdOrRange       ::= CHOICE {
id                ASId,
range             ASRange
}
ASRange           ::= SEQUENCE {
min               ASId,
max               ASId
}
ASId              ::= INTEGER
-- see https://www.rfc-editor.org/rfc/rfc3779.html
   CDDL
 AsIdsOrRanges = uint / [uint, uint]
ASIdentifiers = [ + AsIdsOrRanges ] / null
 NOTE
If rdi is not present, the extension value can be CBOR encoded.
Each ASId is encoded as an uint. With the exception of the first
ASId, the ASid is encoded as the difference to the previous ASid.
*/
fn cbor_ext_as_res(b: &[u8]) -> Vec<u8> {
  let as_identifiers = der(b, ASN1_SEQ);
  let asnum = der(as_identifiers, ASN1_INDEX_ZERO);
  let mut vec = Vec::new();
  let mut last = 0u64;
  if asnum == [0x05, 0x00] {
      return cbor_simple(CBOR_NULL);
  }
  for elem in der_vec(asnum, ASN1_SEQ) {
      if elem[0] == ASN1_INT {
          let asid = be_bytes_to_u64(der_uint(elem));
          vec.push(cbor_uint(asid - last));
          last = asid;
      } else if elem[0] == ASN1_SEQ {
          let mut range = Vec::new();
          for elem2 in der_vec_len(elem, ASN1_SEQ, 2) {
              let asid = be_bytes_to_u64(der_uint(elem2));
              range.push(cbor_uint(asid - last));
              last = asid;
          }
          vec.push(cbor_array(&range));
      } else {
          panic!("Expected INT or SEQ");
      }
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encodes a Authority Key Identifier extension
Description:
Authority Key Identifier (authorityKeyIdentifier). If the authority key identifier
contains all of keyIdentifier, certIssuer, and certSerialNumberm or if only keyIdentifier
is present the extension value can be CBOR encoded. If all three are present a CBOR array
is used, if only keyIdentifier is present, the array is omitted
CDDL
KeyIdentifierArray = [
 keyIdentifier: KeyIdentifier / null,
 authorityCertIssuer: GeneralNames,
 authorityCertSerialNumber: CertificateSerialNumber
]
AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier
*/
fn cbor_ext_auth_key_id(b: &[u8]) -> Vec<u8> {
  let aki = der_vec(b, ASN1_SEQ);
  let ki = cbor_bytes(der(aki[0], 0x80));
  match aki.len() {
      1 => ki,
      3 => cbor_array(&[ki, cbor_general_names(aki[1], 0xa1, 0xff), cbor_bytes(der(aki[2], 0x82))]),
      _ => panic!("Error parsing auth key id"),
  }
}
/******************************************************************************************************/
/*
CBOR encode a Basic Constraints extension
Description
Basic Constraints (basicConstraints). If 'cA' = false then extensionValue = -2, if 'cA' = true and
'pathLenConstraint' is not present then extensionValue = -1, and if 'cA' = true and 'pathLenConstraint'
is present then extensionValue = pathLenConstraint.
CDDL
 BasicConstraints = int
 TODO: check how to distinguish between BC -1 and keyUsage -2
*/
fn cbor_ext_bas_con(b: &[u8]) -> Vec<u8> {
  let bc = der_vec(b, ASN1_SEQ);
  match bc.len() {
      0 => cbor_int(-2),
      1 => {
          assert!(der(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
          cbor_int(-1)
      }
      2 => {
          assert!(der(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
          let path_len = der_uint(bc[1]);
          assert!(path_len.len() == 1, "Expected path length < 256");
          cbor_uint(path_len[0] as u64)
      }
      _ => panic!("Error parsing basic constraints"),
  }
}
/******************************************************************************************************/
/*
CBOR encodes a Certificate Policies extension
ASN.1 input
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
PolicyInformation ::= SEQUENCE {
policyIdentifier   CertPolicyId,
policyQualifiers   SEQUENCE SIZE (1..MAX) OF
        PolicyQualifierInfo OPTIONAL }
CertPolicyId ::= OBJECT IDENTIFIER
CERT-POLICY-QUALIFIER ::= TYPE-IDENTIFIER
PolicyQualifierInfo ::= SEQUENCE {
  policyQualifierId  CERT-POLICY-QUALIFIER.
        &id({PolicyQualifierId}),
  qualifier       CERT-POLICY-QUALIFIER.
        &Type({PolicyQualifierId}{@policyQualifierId})}
PolicyQualifierId CERT-POLICY-QUALIFIER ::=
{ pqid-cps | pqid-unotice, ... }
 CDDL
 PolicyIdentifier = int / ~oid
PolicyQualifierInfo = (
policyQualifierId: int / ~oid,
qualifier: text,
)
CertificatePolicies = [
+ ( PolicyIdentifier, ? [ + PolicyQualifierInfo ] )
]
 NOTE
If noticeRef is not used and any explicitText are encoded as UTF8String, the extension value can be CBOR encoded.
OIDs registered in C509 are encoded as an int. The policyQualifierId is encoded as an CBOR int or an unwrapped
CBOR OID tag (RFC9090).
*/
fn cbor_ext_cert_policies(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  for pi in der_vec(b, ASN1_SEQ) {
      let pi = der_vec(pi, ASN1_SEQ);
      assert!(pi.len() == 1 || pi.len() == 2, "expected length 1 or 2");
      let oid = der(pi[0], ASN1_OID);
      if let Some(cp_type) = cp_map(oid) {
          vec.push(cbor_int(cp_type));
      } else {
          print_warning("No C509 int registered for Certificate Policy OID", pi[0], oid);
          vec.push(cbor_bytes(oid));
      }
      if pi.len() == 2 {
          let mut vec2 = Vec::new();
          for pqi in der_vec(pi[1], ASN1_SEQ) {
              let pqi = der_vec_len(pqi, ASN1_SEQ, 2);
              let oid = der(pqi[0], ASN1_OID);
              if let Some(pq_type) = pq_map(oid) {
                  vec2.push(cbor_int(pq_type));
                  if pq_type == PQ_CPS {
                      let text = der(pqi[1], ASN1_IA5_SRT);
                      vec2.push(cbor_text(text));
                  } else if pq_type == PQ_UNOTICE {
                      let text = der(der(pqi[1], ASN1_SEQ), ASN1_UTF8_STR);
                      vec2.push(cbor_text(text));
                  } else {
                      panic!("unexpected qualifier oid");
                  }
              } else {
                  print_warning("No C509 int registered for Policy Qualifier OID", pqi[0], oid);
                  vec2.push(cbor_bytes(oid));
              }
          }
          vec.push(cbor_array(&vec2));
      }
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
/**
CBOR encodes a CRL distribution list extension
CDDL
DistributionPointName = [ 2* text ] / text
CRLDistributionPoints = [ + DistributionPointName ]
 NOTE
CRL Distribution Points (cRLDistributionPoints). If the CRL Distribution Points is a sequence of
DistributionPointName, where each DistributionPointName only contains uniformResourceIdentifiers,
the extension value can be CBOR encoded. extensionValue is encoded as follows:
*/
fn cbor_ext_crl_dist(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  for dists in der_vec(b, ASN1_SEQ) {
      let dists = der(dists, ASN1_SEQ);
      let dists = der(dists, 0xa0);
      let mut vec2 = Vec::new();
      for dist in der_vec(dists, 0xa0) {
          vec2.push(cbor_text(der(dist, 0x86)));
      }
      if vec2.len() > 1 {
          vec.push(cbor_array(&vec2))
      } else {
          vec.push(vec2[0].clone())
      }
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encodes a extended key usage extension
fn cbor_ext_eku(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  for eku in der_vec(b, ASN1_SEQ) {
      let oid = der(eku, ASN1_OID);
      if let Some(eku_type) = eku_map(oid) {
          vec.push(cbor_uint(eku_type));
      } else {
          print_warning("No C509 int registered for EKU OID", eku, oid);
          vec.push(cbor_bytes(oid));
      }
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encodes a authority/subject Info Access extension
fn cbor_ext_info_access(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  for access_desc in der_vec(b, ASN1_SEQ) {
      let access_desc = der_vec_len(access_desc, ASN1_SEQ, 2);
      let oid = der(access_desc[0], ASN1_OID);
      let access_location = cbor_text(der(access_desc[1], 0x86));
      if let Some(access_type) = info_map(oid) {
          vec.push(cbor_int(access_type));
      } else {
          print_warning("No C509 int registered for Info Access OID", access_desc[0], oid);
          vec.push(cbor_bytes(oid));
      }
      vec.push(access_location);
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
/******************************************************************************************************/
// CBOR encodes a Range of IP Addresses
fn cbor_ext_ip_res(b: &[u8]) -> Vec<u8> {
  let mut vec = Vec::new();
  let mut last = Vec::new();
  for block in der_vec(b, ASN1_SEQ) {
      let family = der_vec_len(block, ASN1_SEQ, 2);
      let afi = der(family[0], ASN1_OCTET_STR);
      assert!(afi.len() == 2, "expected afi and no safi");
      vec.push(cbor_uint(be_bytes_to_u64(afi)));
      // NULL
      let mut fam = Vec::new();
      for aor in der_vec(family[1], ASN1_SEQ) {
          if aor[0] == ASN1_BIT_STR {
              let ip = der(aor, ASN1_BIT_STR);
              let unused_bits = ip[0];
              let ip_bytes = &ip[1..];
              if ip_bytes.len() == last.len() {
                  let diff = be_bytes_to_u64(ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                  fam.push(cbor_int(diff));
              } else {
                  fam.push(cbor_bytes(&ip_bytes));
              }
              last = ip_bytes.to_vec();
              fam.push(cbor_uint(unused_bits as u64));
          } else if aor[0] == ASN1_SEQ {
              let mut range = Vec::new();
              let range_der = der_vec_len(aor, ASN1_SEQ, 2);
              let ip = der(range_der[0], ASN1_BIT_STR);
              let ip_bytes = &ip[1..];
              if ip_bytes.len() == last.len() {
                  let diff = be_bytes_to_u64(ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                  range.push(cbor_int(diff));
              } else {
                  range.push(cbor_bytes(&ip_bytes));
              }
              last = ip_bytes.to_vec();
              let ip = der(range_der[1], ASN1_BIT_STR);
              let unused_bits = ip[0];
              let mut ip_bytes = ip[1..].to_vec();
              let l = ip_bytes.len();
              ip_bytes[l - 1] |= (2u16.pow(unused_bits as u32) - 1) as u8;
              if ip_bytes.len() == last.len() {
                  let diff = be_bytes_to_u64(&ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                  range.push(cbor_int(diff));
              } else {
                  range.push(cbor_bytes(&ip_bytes));
              }
              last = ip_bytes.to_vec();
              fam.push(cbor_array(&range));
          } else {
              panic!("Expected INT or SEQ");
          }
      }
      vec.push(cbor_array(&fam));
  }
  cbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encode EXT_KEY_USAGE - 2 - Key Usage Extension
*/
fn cbor_ext_key_use(bs: &[u8], signed_nr_ext: i64) -> Vec<u8> {
  assert!(bs[0] == ASN1_BIT_STR, "Expected 0x03");
  let len = bs[1];
  assert!((2..4).contains(&len), "Expected key usage ASN.1 field len to be 2 or 3 bytes");
  //Note: at encoding time we don't need to handle bs[2] / the number of free bytes
  let v = bs[3].swap_bits();
  if len == 3 {
      assert!(bs[4] == 128, "Error in KeyUsage bitstring, more than 9 bits used");
      let w = (v as u64) + 256;
      if signed_nr_ext == -1 {
          return cbor_int(-(w as i64));
      }
      return cbor_uint(w as u64);
  }
  if signed_nr_ext == -1 {
      return cbor_int(-(v as i64));
  }
  cbor_uint(v as u64)
}
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// CBOR encodes a SCT extention
// https://letsencrypt.org/2018/04/04/sct-encoding.html
// refactor signature calculation
fn cbor_ext_sct(b: &[u8], not_before: &[u8]) -> Vec<u8> {
  let mut temp = &der(b, ASN1_OCTET_STR)[2..];
  let mut scts = Vec::new();
  while !temp.is_empty() {
      let end = ((temp[0] as usize) << 8) + (temp[1] as usize);
      let (value, temp2) = (&temp[2..2 + end], &temp[2 + end..]);
      scts.push(value);
      temp = temp2;
  }
  let mut vec = Vec::new();
  for sct in scts {
      assert!(sct[0] == 0, "expected SCT version 1");
      vec.push(cbor_bytes(&sct[1..33]));
      let ts = be_bytes_to_u64(&sct[33..41]) as i64;
      let not_before_ms = 1000 * be_bytes_to_u64(&cbor_time(not_before)[1..]) as i64;
      vec.push(cbor_int(ts - not_before_ms));
      assert!(sct[41..43] == [0, 0], "expected no SCT extentsions");
      assert!(sct[43..45] == [4, 3], "expected SCT SHA-256 ECDSA");
      vec.push(cbor_int(SIG_ECDSA_SHA256 as i64));
      let signature_seq = der_vec(&sct[47..], ASN1_SEQ);
      let r = der_uint(signature_seq[0]).to_vec();
      let s = der_uint(signature_seq[1]).to_vec();
      let max = std::cmp::max(r.len(), s.len());
      let signature_ecdsa = &[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat();
      vec.push(cbor_bytes(signature_ecdsa));
  }
  cbor_array(&vec)
}
/*fn cbor_ext_store_only(b: &[u8]) -> Vec<u8> {
}
*//*
Above is the list of encoding functions for the supported extensions listed in C509 Extensions Registry
*/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
fn print_information(certs: &[Cert]) {
  // calculate lengths for printing
  let der_len: u64 = certs.iter().map(|v| v.der.len() as u64).sum();
  let cbor_len: u64 = certs.iter().map(|v| v.cbor.concat().len() as u64).sum();
  // print general information
  let row1 = format!("Encoding certificate chain/bag with {} certificates", certs.len());
  let row2 = format!("{} bytes / {} bytes ({:.2}%)", cbor_len, der_len, 100.0 * cbor_len as f64 / der_len as f64);
  print_info(&[row1, row2]);
  // Print information about individual certs
  for (i, cert) in certs.iter().enumerate() {
      let row1 = format!("Encoding certificate {} of {}", i + 1, certs.len());
      let row2 = format!("{} bytes / {} bytes ({:.2}%)", cert.cbor.concat().len(), cert.der.len(), 100.0 * cert.cbor.concat().len() as f64 / cert.der.len() as f64);
      print_info(&[row1, row2]);
      if PRINT_INPUT {
          print_vec("Input: DER encoded X.509 certificate (RFC 5280)", &cert.der);
      }
      if PRINT_OUTPUT {
          print_vec("Output: CBOR encoded X.509 certificate (~C509Certificate)", &cert.cbor.concat());
          print_vec("C509 Certificate Type", &cert.cbor[0]);
          print_vec("Certificate Serial Number", &cert.cbor[1]);
          print_vec("Issuer", &cert.cbor[2]);
          print_vec("Validity Not Before", &cert.cbor[3]);
          print_vec("Validity Not After", &cert.cbor[4]);
          print_vec("Subject", &cert.cbor[5]);
          print_vec("Subject Public Key Algorithm", &cert.cbor[6]);
          print_vec("Subject Public Key", &cert.cbor[7]);
          print_vec("Extentions", &cert.cbor[8]);
          print_vec("Issuer Signature Algorithm", &cert.cbor[9]);
          print_vec("Issuer Signature Value", &cert.cbor[10]);
      }
  }
  if PRINT_COSE {
      // COSE_X509
      // ======================================================
      let row1 = format!("CBOR COSE_X509 with {} certificates", certs.len());
      print_info(&[row1]);
      if certs.len() > 1 {
          let mut cose_x509: Vec<Vec<u8>> = Vec::new();
          for cert in certs {
              cose_x509.push(cbor_bytes(&cert.der));
          }
          print_vec("COSE_X509", &cbor_array(&cose_x509));
      } else {
          print_vec("COSE_X509", &cbor_bytes(&certs[0].der));
      }
      // COSE_C509
      // ======================================================
      let row1 = format!("CBOR COSE_C509 with {} certificates", certs.len());
      print_info(&[row1]);
      if certs.len() > 1 {
          let mut cose_c509: Vec<Vec<u8>> = Vec::new();
          for cert in certs {
              cose_c509.push(cbor_array(&cert.cbor));
          }
          print_vec("COSE_C509", &cbor_array(&cose_c509));
      } else {
          print_vec("COSE_X509", &cbor_array(&certs[0].cbor));
      }
      // // COSE_C509 Uncompressed
      // // ======================================================
      // let row1 = format!("CBOR COSE_C509 Uncompressed with {} certificates", certs.len());
      // print_info(&[row1]);
      // let mut cose_c509: Vec<Vec<u8>> = vec![cbor_uint(0)];
      // for cert in certs {
      //  cose_c509.push(cbor_array(&cert.cbor));
      // }
      // print_vec("COSE_C509 Uncompressed", &cbor_array(&cose_c509));
      // // COSE_C509 Brotli
      // // ======================================================
      // let row1 = format!("CBOR COSE_C509 Brotli with {} certificates", certs.len());
      // print_info(&[row1]);
      // let mut cose_c509: Vec<Vec<u8>> = vec![cbor_uint(1)];
      // let mut certs2: Vec<Vec<u8>> = Vec::new();
      // for cert in certs {
      //  certs2.push(cbor_array(&cert.cbor));
      // }
      // cose_c509.push(cbor_bytes(&brotli(&certs2.concat())));
      // print_vec("COSE_C509 Brotli", &cbor_array(&cose_c509));
  }
  if PRINT_TLS {
      // TLS 1.3 Certificate message (X509)
      // ======================================================
      let row1 = format!("TLS 1.3 Certificate message with {} certificates (X509)", certs.len());
      print_info(&[row1]);
      let mut tls_x509 = Vec::new();
      for cert in certs {
          tls_x509.extend(&(cert.der.len() as u32).to_be_bytes()[1..4]);
          tls_x509.extend(&cert.der);
          tls_x509.extend(&[0x00, 0x00]);
      }
      tls_x509 = [&[0x00], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509].concat();
      tls_x509 = [&[0x0b], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509].concat();
      print_vec("TLS_X509", &tls_x509);
      // TLS 1.3 CompressedCertificate message (X509 + Brotli)
      // ======================================================
      let row1 = "TLS 1.3 CompressedCertificate message (X509 + Brotli)".to_string();
      print_info(&[row1]);
      let mut tls_x509_brotli = brotli(&tls_x509);
      tls_x509_brotli = [&(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
      tls_x509_brotli = [&[0x00, 0x02], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
      tls_x509_brotli = [&[0x19], &(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
      print_vec("Brotli TLS_X509", &tls_x509_brotli);
      // TLS 1.3 Certificate message (C509)
      // ======================================================
      let row1 = format!("TLS 1.3 Certificate message with {} certificates (C509)", certs.len());
      print_info(&[row1]);
      let mut tls_c509 = Vec::new();
      for cert in certs {
          tls_c509.extend(&(cert.cbor.concat().len() as u32).to_be_bytes()[1..4]);
          tls_c509.extend(&cert.cbor.concat());
          tls_c509.extend(&[0x00, 0x00]);
      }
      tls_c509 = [&[0x00], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509].concat();
      tls_c509 = [&[0x0b], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509].concat();
      print_vec("TLS_C509", &tls_c509);
      // TLS 1.3 CompressedCertificate message (X509 + Brotli)
      // ======================================================
      let row1 = "TLS 1.3 CompressedCertificate message (C509 + Brotli)".to_string();
      print_info(&[row1]);
      let mut tls_c509_brotli = brotli(&tls_c509);
      tls_c509_brotli = [&(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
      tls_c509_brotli = [&[0x00, 0x02], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
      tls_c509_brotli = [&[0x19], &(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
      print_vec("Brotli TLS_C509", &tls_c509_brotli);
  }
}
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// ======================================================
// C509 maps for OID and ALD_ID to int
// ======================================================
// C509 Certificate Attributes Registry
// ======================================================
pub const ATT_EMAIL: u32 = 0;
pub const ATT_COMMON_NAME: u32 = 1; // CN
pub const ATT_SUR_NAME: u32 = 2; // SN
pub const ATT_SERIAL_NUMBER: u32 = 3;
pub const ATT_COUNTRY: u32 = 4; // C
pub const ATT_LOCALITY: u32 = 5; // L
pub const ATT_STATE_OR_PROVINCE: u32 = 6; // ST
pub const ATT_STREET_ADDRESS: u32 = 7;
pub const ATT_ORGANIZATION: u32 = 8; // O
pub const ATT_ORGANIZATION_UNIT: u32 = 9; // OU
pub const ATT_TITLE: u32 = 10; // T
pub const ATT_BUSINESS: u32 = 11;
pub const ATT_POSTAL_CODE: u32 = 12; // PC
pub const ATT_GIVEN_NAME: u32 = 13;
pub const ATT_INITIALS: u32 = 14;
pub const ATT_GENERATION_QUALIFIER: u32 = 15;
pub const ATT_DN_QUALIFIER: u32 = 16;
pub const ATT_PSEUDONYM: u32 = 17;
pub const ATT_ORGANIZATION_IDENTIFIER: u32 = 18;
pub const ATT_INC_LOCALITY: u32 = 19;
pub const ATT_INC_STATE: u32 = 20;
pub const ATT_INC_COUNTRY: u32 = 21;
pub const ATT_DOMAIN_COMPONENT: u32 = 22; // DC
                                      
pub const ATT_POSTAL_ADDRESS: u32 = 24; //postalAddress,  55 04 10
pub const ATT_NAME: u32 = 25; //name,           55 04 29
pub const ATT_TELEPHONE_NUMBER: u32 = 26; //telephoneNumber 55 04 14
pub const ATT_DIR_MAN_DOMAIN_NAME: u32 = 27; //dmdName      55 04 36
pub const ATT_USER_ID: u32 = 28; //uid             09 92 26 89 93 F2 2C 64 01 01
pub const ATT_UNSTRUCTURED_NAME: u32 = 29; //unstructuredName         2A 86 48 86 F7 0D 01 09 02
pub const ATT_UNSTRUCTURED_ADDRESS: u32 = 30; //unstructuredAddress   2A 86 48 86 F7 0D 01 09 08 00
pub fn att_map(oid: &[u8]) -> Option<u32> {
  match oid {
      [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, ..] => match oid[9..] {
          [0x01] => Some(ATT_USER_ID),
          [0x19] => Some(ATT_DOMAIN_COMPONENT),
          _ => None,
      },
      [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, ..] => match oid[8..] {
          [0x01] => Some(ATT_EMAIL),
          [0x02] => Some(ATT_UNSTRUCTURED_NAME),
          [0x08, 0x00] => Some(ATT_UNSTRUCTURED_ADDRESS),
          _ => None,
      },
      [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, ..] => match oid[10..] {
          [0x01] => Some(ATT_INC_LOCALITY),
          [0x02] => Some(ATT_INC_STATE),
          [0x03] => Some(ATT_INC_COUNTRY),
          _ => None,
      },
      [0x55, 0x04, ..] => match oid[2..] {
          [0x03] => Some(ATT_COMMON_NAME),
          [0x04] => Some(ATT_SUR_NAME),
          [0x05] => Some(ATT_SERIAL_NUMBER),
          [0x06] => Some(ATT_COUNTRY),
          [0x07] => Some(ATT_LOCALITY),
          [0x08] => Some(ATT_STATE_OR_PROVINCE),
          [0x09] => Some(ATT_STREET_ADDRESS),
          [0x10] => Some(ATT_POSTAL_ADDRESS),
          [0x14] => Some(ATT_TELEPHONE_NUMBER),
          [0x0A] => Some(ATT_ORGANIZATION),
          [0x0B] => Some(ATT_ORGANIZATION_UNIT),
          [0x0C] => Some(ATT_TITLE),
          [0x0F] => Some(ATT_BUSINESS),
          [0x11] => Some(ATT_POSTAL_CODE),
          [0x29] => Some(ATT_NAME),
          [0x2A] => Some(ATT_GIVEN_NAME),
          [0x2B] => Some(ATT_INITIALS),
          [0x2C] => Some(ATT_GENERATION_QUALIFIER),
          [0x2E] => Some(ATT_DN_QUALIFIER),
          [0x36] => Some(ATT_DIR_MAN_DOMAIN_NAME),
          [0x41] => Some(ATT_PSEUDONYM),
          [0x61] => Some(ATT_ORGANIZATION_IDENTIFIER),
          _ => None,
      },
      _ => None,
  }
}
// C509 Certificate Public Key Algorithms Registry
// Ongoing / still TODO: find test certs for PK_SM2P256V1
// ======================================================
pub const PK_RSA_ENC: i64 = 0;
pub const PK_SECP256R: i64 = 1;
pub const PK_SECP384R: i64 = 2;
pub const PK_SECP521R: i64 = 3;
pub const PK_X25519: i64 = 8;
pub const PK_X448: i64 = 9;
pub const PK_ED25519: i64 = 10;
pub const PK_ED448: i64 = 11;
pub const PK_HSS_LMS: i64 = 17;
pub const PK_XMSS: i64 = 18;
pub const PK_XMSS_MT: i64 = 19;
pub const PK_BRAINPOOL256R1: i64 = 24;
pub const PK_BRAINPOOL384R1: i64 = 25;
pub const PK_BRAINPOOL512R1: i64 = 26;
pub const PK_FRP256V1: i64 = 27;
pub const PK_SM2P256V1: i64 = 28; //06 07 2A 86 48 CE 3D 02 01 06 08 2A 81 1C CF 55 01 82 2D
pub fn pk_map(alg_id: &[u8]) -> Option<i64> {
  let value = der(alg_id, ASN1_SEQ);
  match value {
      [0x06, 0x03, 0x2B, 0x65, ..] => match value[4..] {
          [0x6E] => Some(PK_X25519),
          [0x6F] => Some(PK_X448),
          [0x70] => Some(PK_ED25519),
          [0x71] => Some(PK_ED448),
          _ => None,
      },
      [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, ..] => match der(&value[9..], ASN1_OID) {
          [0x2A, 0x81, 0x7A, 0x01, 0x81, 0x5F, 0x65, 0x82, 0x00, 0x01] => Some(PK_FRP256V1),
          [0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D] => Some(PK_SM2P256V1),
          [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => Some(PK_SECP256R),
          [0x2B, 0x81, 0x04, 0x00, 0x22] => Some(PK_SECP384R),
          [0x2B, 0x81, 0x04, 0x00, 0x23] => Some(PK_SECP521R),
          [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => Some(PK_BRAINPOOL256R1),
          [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B] => Some(PK_BRAINPOOL384R1),
          [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D] => Some(PK_BRAINPOOL512R1),
          _ => None,
      },
      [0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x0F, 0x01, 0x01, ..] => match value[4..] {
          [0x0D, 0x00] => Some(PK_XMSS),
          [0x0E, 0x00] => Some(PK_XMSS_MT),
          _ => None,
      },
      [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00] => Some(PK_RSA_ENC),
      [0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x11] => Some(PK_HSS_LMS),
      _ => None,
  }
}
// C509 Certificate Signature Algorithms Registry
// Ongoing / still TODO: find tests for 16--18 + 45
// ======================================================
pub const SIG_RSA_V15_SHA1: i64 = -256;
pub const SIG_ECDSA_SHA1: i64 = -255;
pub const SIG_ECDSA_SHA256: i64 = 0;
pub const SIG_ECDSA_SHA384: i64 = 1;
pub const SIG_ECDSA_SHA512: i64 = 2;
pub const SIG_ECDSA_SHAKE128: i64 = 3;
pub const SIG_ECDSA_SHAKE256: i64 = 4;
pub const SIG_ED25519: i64 = 12;
pub const SIG_ED448: i64 = 13;
pub const SIG_HSS_LMS: i64 = 16; //30 0D 06 0B 2A 86 48 86 F7 0D 01 09 10 03 11
pub const SIG_XMSS: i64 = 17; //30 0B 06 09 04 00 7F 00 0F 01 01 0D 00
pub const SIG_XMSS_MT: i64 = 18; //30 0B 06 09 04 00 7F 00 0F 01 01 0E 00
pub const SIG_RSA_V15_SHA256: i64 = 23;
pub const SIG_RSA_V15_SHA384: i64 = 24;
pub const SIG_RSA_V15_SHA512: i64 = 25;
pub const SIG_RSA_PSS_SHA256: i64 = 26;
pub const SIG_RSA_PSS_SHA384: i64 = 27;
pub const SIG_RSA_PSS_SHA512: i64 = 28;
pub const SIG_RSA_PSS_SHAKE128: i64 = 29;
pub const SIG_RSA_PSS_SHAKE256: i64 = 30;
pub const SIG_SM2_V15_SM3: i64 = 45; //30 0A 06 08 2A 81 1C CF 55 01 83 75
pub fn sig_map(alg_id: &[u8]) -> Option<i64> {
  let value = der(alg_id, ASN1_SEQ);
  match value {
      [0x06, 0x03, 0x2B, 0x65, ..] => match value[4..] {
          [0x70] => Some(SIG_ED25519),
          [0x71] => Some(SIG_ED448),
          _ => None,
      },
      [0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75] => Some(SIG_SM2_V15_SM3),
      [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, ..] => match value[9..] {
          [0x01] => Some(SIG_ECDSA_SHA1),
          [0x02] => Some(SIG_ECDSA_SHA256),
          [0x03] => Some(SIG_ECDSA_SHA384),
          [0x04] => Some(SIG_ECDSA_SHA512),
          _ => None,
      },
      [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, ..] => match value[9..] {
          [0x20] => Some(SIG_ECDSA_SHAKE128),
          [0x21] => Some(SIG_ECDSA_SHAKE256),
          [0x1E] => Some(SIG_RSA_PSS_SHAKE128),
          [0x1F] => Some(SIG_RSA_PSS_SHAKE256),
          _ => None,
      },
      [0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x0f, 0x01, 0x01, ..] => match value[9..] {
          [0x0d, 0x00] => Some(SIG_XMSS),
          [0x0e, 0x00] => Some(SIG_XMSS_MT),
          _ => None,
      },
      [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, ..] => match value[10..] {
          [0x05, 0x05, 0x00] => Some(SIG_RSA_V15_SHA1),
          [0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, ..] => match value[27..] {
              [0x01, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20] => {
                  Some(SIG_RSA_PSS_SHA256)
              }
              [0x02, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30] => {
                  Some(SIG_RSA_PSS_SHA384)
              }
              [0x03, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x40] => {
                  Some(SIG_RSA_PSS_SHA512)
              }
              _ => None,
          },
          [0x0B, 0x05, 0x00] => Some(SIG_RSA_V15_SHA256),
          [0x0C, 0x05, 0x00] => Some(SIG_RSA_V15_SHA384),
          [0x0D, 0x05, 0x00] => Some(SIG_RSA_V15_SHA512),
          _ => None,
      },
      [0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x11] => Some(SIG_HSS_LMS),
      _ => None,
  }
}
// C509 Certificate Extensions Registry *updated*
// ======================================================
pub const EXT_SUBJECT_KEY_ID: u16 = 1;
pub const EXT_KEY_USAGE: u16 = 2;
pub const EXT_SUBJECT_ALT_NAME: u16 = 3;
pub const EXT_BASIC_CONSTRAINTS: u16 = 4;
pub const EXT_CRL_DIST_POINTS: u16 = 5;
pub const EXT_CERT_POLICIES: u16 = 6;
pub const EXT_AUTH_KEY_ID: u16 = 7;
pub const EXT_EXT_KEY_USAGE: u16 = 8;
pub const EXT_AUTH_INFO: u16 = 9;
pub const EXT_SCT_LIST: u16 = 10;
pub const EXT_SUBJECT_DIRECTORY_ATTR: u16 = 24; //0x09
pub const EXT_ISSUER_ALT_NAME: u16 = 25; //0x12
pub const EXT_NAME_CONSTRAINTS: u16 = 26; //0x1E
pub const EXT_POLICY_MAPPINGS: u16 = 27; //21
pub const EXT_POLICY_CONSTRAINTS: u16 = 28; //24
pub const EXT_FRESHEST_CRL: u16 = 29; //2e
pub const EXT_INHIBIT_ANYPOLICY: u16 = 30; //36
pub const EXT_SUBJECT_INFO_ACCESS: u16 = 31; //5-0b
pub const EXT_IP_RESOURCES: u16 = 32; //5-07
pub const EXT_AS_RESOURCES: u16 = 33; //5-08
pub const EXT_IP_RESOURCES_V2: u16 = 34; //5-1c
pub const EXT_AS_RESOURCES_V2: u16 = 35; //5-1d
pub const EXT_BIOMETRIC_INFO: u16 = 36; //5-02
pub const EXT_PRECERT_SIGNING_CERT: u16 = 37; //4-04
pub const EXT_OCSP_NO_CHECK: u16 = 38; //2B 06 01 05 05 07 30 01 05
pub const EXT_QUALIFIED_CERT_STATEMENTS: u16 = 39; //5-03
pub const EXT_S_MIME_CAPABILITIES: u16 = 40; //2A 86 48 86 F7 0D 01 09 0F
pub const EXT_TLS_FEATURES: u16 = 41; //5-18
pub const EXT_CHALLENGE_PASSWORD: u16 = 255;

pub fn ext_map(oid: &[u8]) -> Option<u16> {
  match oid {      
      [0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, ..] => match oid[9] {
          0x02 => Some(EXT_SCT_LIST),
          0x04 => Some(EXT_PRECERT_SIGNING_CERT),
          _ => None,
      },
      [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, ..] => match oid[7] {
          0x01 => Some(EXT_AUTH_INFO),
          0x02 => Some(EXT_BIOMETRIC_INFO),
          0x03 => Some(EXT_QUALIFIED_CERT_STATEMENTS),
          0x07 => Some(EXT_IP_RESOURCES),
          0x08 => Some(EXT_AS_RESOURCES),
          0x0B => Some(EXT_SUBJECT_INFO_ACCESS),
          0x18 => Some(EXT_TLS_FEATURES),
          0x1C => Some(EXT_IP_RESOURCES_V2),
          0x1D => Some(EXT_AS_RESOURCES_V2),
          _ => None,
      },
      [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05] => Some(EXT_OCSP_NO_CHECK),
      [0x2B, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F] => Some(EXT_S_MIME_CAPABILITIES),
      [0x55, 0x1D, ..] => match oid[2] {
          0x09 => Some(EXT_SUBJECT_DIRECTORY_ATTR),
          0x0E => Some(EXT_SUBJECT_KEY_ID),
          0x0F => Some(EXT_KEY_USAGE),
          0x11 => Some(EXT_SUBJECT_ALT_NAME),
          0x12 => Some(EXT_ISSUER_ALT_NAME),
          0x13 => Some(EXT_BASIC_CONSTRAINTS),
          0x1E => Some(EXT_NAME_CONSTRAINTS),
          0x1F => Some(EXT_CRL_DIST_POINTS),
          0x20 => Some(EXT_CERT_POLICIES),
          0x21 => Some(EXT_POLICY_MAPPINGS),
          0x23 => Some(EXT_AUTH_KEY_ID),
          0x24 => Some(EXT_POLICY_CONSTRAINTS),
          0x25 => Some(EXT_EXT_KEY_USAGE),
          0x2E => Some(EXT_FRESHEST_CRL),
          0x36 => Some(EXT_INHIBIT_ANYPOLICY),
          _ => None,
      },
      _ => None,
  }
}
// C509 Certificate Extended Key Usages Registry
// ======================================================
pub const EKU_TLS_SERVER: u64 = 1;
pub const EKU_TLS_CLIENT: u64 = 2;
pub const EKU_CODE_SIGNING: u64 = 3;
pub const EKU_EMAIL_PROTECTION: u64 = 4;
pub const EKU_TIME_STAMPING: u64 = 8;
pub const EKU_OCSP_SIGNING: u64 = 9;
/* Updated */
pub const EKU_ANY_EKU: u64 = 0;                      //55 1D 25 00
pub const EKU_KERBEROS_PKINIT_CLIENT_AUTH: u64 = 10; //2B 06 01 05 02 03 04
pub const EKU_KERBEROS_PKINIT_KDC: u64 = 11;         //2B 06 01 05 02 03 05
pub const EKU_SSH_CLIENT: u64 = 12;                  //15
pub const EKU_SSH_SERVER: u64 = 13;                  //16
pub const EKU_BUNDLE_SECURITY: u64 = 14;             //23
pub const EKU_CMC_CERT_AUTHORITY: u64 = 15;          //1b
pub const EKU_CMC_REG_AUTHORITY: u64 = 16;           //1c
pub const EKU_CMC_ARCHIVE_SERVER: u64 = 17;          //1d
pub const EKU_CMC_KEY_GEN_AUTHORITY: u64 = 18;       //20
pub fn eku_map(oid: &[u8]) -> Option<u64> {
  match oid {
      [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, ..] => match oid[6] {
          0x04 => Some(EKU_KERBEROS_PKINIT_CLIENT_AUTH),
          0x05 => Some(EKU_KERBEROS_PKINIT_KDC),
          _ => None,
      },
      [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, ..] => match oid[7] {
          0x01 => Some(EKU_TLS_SERVER),
          0x02 => Some(EKU_TLS_CLIENT),
          0x03 => Some(EKU_CODE_SIGNING),
          0x04 => Some(EKU_EMAIL_PROTECTION),
          0x08 => Some(EKU_TIME_STAMPING),
          0x09 => Some(EKU_OCSP_SIGNING),
          0x15 => Some(EKU_SSH_CLIENT),
          0x16 => Some(EKU_SSH_SERVER),
          0x1b => Some(EKU_CMC_CERT_AUTHORITY),
          0x2c => Some(EKU_CMC_REG_AUTHORITY),
          0x2d => Some(EKU_CMC_ARCHIVE_SERVER),
          0x20 => Some(EKU_CMC_ARCHIVE_SERVER),
          0x23 => Some(EKU_BUNDLE_SECURITY),
          _ => None,
      },
      [0x55, 0x1D, 0x25, 0x00] => Some(EKU_ANY_EKU),
      _ => None,
  }
}
// C509 Certificate Policies Registry
// ======================================================
//TODO: check/test CP_RSP_ROLE_DS_AUTH
pub const CP_ANY_POLICY: i64 = 0;
pub const CP_DOMAIN_VALIDATION: i64 = 1; // DV
pub const CP_ORGANIZATION_VALIDATION: i64 = 2; // OV
pub const CP_INDIVIDUAL_VALIDATION: i64 = 3; // IV
pub const CP_EXTENDED_VALIDATION: i64 = 4; // EV
pub const CP_RESOURCE_PKI: i64 = 7; // RPKI
pub const CP_RESOURCE_PKI_ALT: i64 = 8;
pub const CP_RSP_ROLE_CI: i64 = 10; // Certificate Issuer
pub const CP_RSP_ROLE_EUICC: i64 = 11;
pub const CP_RSP_ROLE_EUM: i64 = 12; // eUICC Manufacturer
pub const CP_RSP_ROLE_DP_TLS: i64 = 13; // SM-DP+ TLS
pub const CP_RSP_ROLE_DP_AUTH: i64 = 14; // SM-DP+ Authentication
pub const CP_RSP_ROLE_DP_PB: i64 = 15; // SM-DP+ Profile Binding
pub const CP_RSP_ROLE_DS_TLS: i64 = 16; // SM-DS TLS
pub const CP_RSP_ROLE_DS_AUTH: i64 = 17; // SM-DS Authentication, 06 07 67 81 12 01 02 01 07
pub fn cp_map(oid: &[u8]) -> Option<i64> {
  match oid {
      [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0E, ..] => match oid[7..] {
          [0x02] => Some(CP_RESOURCE_PKI),
          [0x03] => Some(CP_RESOURCE_PKI_ALT),
          _ => None,
      },
      [0x55, 0x1D, 0x20, 0x00] => Some(CP_ANY_POLICY),
      [0x67, 0x81, 0x0C, 0x01, ..] => match oid[4..] {
          [0x01] => Some(CP_EXTENDED_VALIDATION),
          [0x02, 0x01] => Some(CP_DOMAIN_VALIDATION),
          [0x02, 0x02] => Some(CP_ORGANIZATION_VALIDATION),
          [0x02, 0x03] => Some(CP_INDIVIDUAL_VALIDATION),
          _ => None,
      },
      [0x67, 0x81, 0x12, 0x01, 0x02, 0x01, ..] => match oid[6..] {
          [0x00] => Some(CP_RSP_ROLE_CI),
          [0x01] => Some(CP_RSP_ROLE_EUICC),
          [0x02] => Some(CP_RSP_ROLE_EUM),
          [0x03] => Some(CP_RSP_ROLE_DP_TLS),
          [0x04] => Some(CP_RSP_ROLE_DP_AUTH),
          [0x05] => Some(CP_RSP_ROLE_DP_PB),
          [0x06] => Some(CP_RSP_ROLE_DS_TLS),
          [0x07] => Some(CP_RSP_ROLE_DS_AUTH),
          _ => None,
      },
      _ => None,
  }
}
// C509 Policies Qualifiers Registry
// ======================================================
pub const PQ_CPS: i64 = 1;
pub const PQ_UNOTICE: i64 = 2;
pub fn pq_map(oid: &[u8]) -> Option<i64> {
  match oid {
      [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, ..] => match oid[7..] {
          [0x01] => Some(PQ_CPS),
          [0x02] => Some(PQ_UNOTICE),
          _ => None,
      },
      _ => None,
  }
}
// C509 Information Access Registry
// ======================================================
pub const INFO_OCSP: i64 = 1;
pub const INFO_CA_ISSUERS: i64 = 2;
pub const INFO_TIME_STAMPING: i64 = 3;
pub const INFO_CA_REPOSITORY: i64 = 5;
pub const INFO_RPKI_MANIFEST: i64 = 10;
pub const INFO_SIGNED_OBJECT: i64 = 11;
pub const INFO_RPKI_NOTIFY: i64 = 13;
pub fn info_map(oid: &[u8]) -> Option<i64> {
  match oid {
      [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, ..] => match oid[7..] {
          [0x01] => Some(INFO_OCSP),
          [0x02] => Some(INFO_CA_ISSUERS),
          [0x03] => Some(INFO_TIME_STAMPING),
          [0x05] => Some(INFO_CA_REPOSITORY),
          [0x0A] => Some(INFO_RPKI_MANIFEST),
          [0x0B] => Some(INFO_SIGNED_OBJECT),
          [0x0D] => Some(INFO_RPKI_NOTIFY),
          _ => None,
      },
      _ => None,
  }
}
// ======================================================
// General helper functions
// ======================================================
pub mod help {
  use colored::*;
  use oid::prelude::*;
  use std::io::Write;
  // Convert a byte string to u64 uint
  pub fn be_bytes_to_u64(b: &[u8]) -> u64 {
      let l = b.len();
      assert!(l > 0 && l < 9, "Unexpected length");
      (0..l).into_iter().map(|i| (b[i] as u64) << (8 * (l - i - 1))).sum()
  }
  // Brotli compression
  pub fn brotli(input: &[u8]) -> Vec<u8> {
      let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
      writer.write_all(input).unwrap();
      writer.into_inner()
  }
  // Print a vec to cout
  fn print_internal(s: &str, v: &[u8], is_error: bool) {
      let heading = format!("{} ({} bytes)", s, v.len());
      if is_error {
          print!("{}", heading.red());
      } else {
          print!("{}", heading.yellow());
      }
      for (i, byte) in v.iter().enumerate() {
          print!("{}{:02X}", if i % 23 == 0 { "\n" } else { " " }, byte);
      }
      println!("\n");
  }
  // Print an error to cout (red and white)
  pub fn print_vec(s: &str, v: &[u8]) {
      print_internal(s, v, false);
  }
  // Print an error to cout (red and white)
  pub fn print_warning(s: &str, v: &[u8], oid: &[u8]) {
      let oid_str: String = ObjectIdentifier::try_from(oid).unwrap().into();
      let text = format!("{} ({})", s, oid_str);
      print_internal(&text, v, true);
  }
  // Print info to cout (green)
  pub fn print_info(rows: &[String]) {
      println!("{}", "--------------------------------------------------------------------".green());
      for row in rows {
          println!("{}", row.green());
      }
      println!("{}", "--------------------------------------------------------------------".green());
      println!();
  }
}
// =========================================================================================================
// DER parsing functions
// =========================================================================================================
pub mod der {
  use crate::help::*;
  // Universal ASN1 tags
  pub const ASN1_BOOL: u8 = 0x01;
  pub const ASN1_INT: u8 = 0x02;
  pub const ASN1_BIT_STR: u8 = 0x03;
  pub const ASN1_OCTET_STR: u8 = 0x04;
  pub const ASN1_OID: u8 = 0x06;
  pub const ASN1_UTF8_STR: u8 = 0x0C;
  pub const ASN1_PRINT_STR: u8 = 0x13;
  pub const ASN1_IA5_SRT: u8 = 0x16;
  pub const ASN1_UTC_TIME: u8 = 0x17;
  pub const ASN1_GEN_TIME: u8 = 0x18;
  pub const ASN1_SEQ: u8 = 0x30;
  pub const ASN1_SET: u8 = 0x31;
  pub const ASN1_INDEX_ZERO: u8 = 0xa0;
  pub const ASN1_INDEX_ONE: u8 = 0xa1;
  // Parse a DER encoded type and returns the value as a byte string
  pub fn der(b: &[u8], tag: u8) -> &[u8] {
      assert!(b[0] == tag, "Unexpected type! Expected {:x} but got {:x}", tag, b[0]);
      let (value, none) = der_split(b, true);
      assert!(none.is_empty(), "Expected empty slice!");
      value
  }
  // Parse a DER encoded uint and removes the first zero byte
  pub fn der_uint(b: &[u8]) -> &[u8] {
      let value = der(b, ASN1_INT);
      if value.len() > 1 && value[0] == 0 {
          return &value[1..];
      }
      value
  }
  // Parse a DER encoded sequence/set type and returns the elements as a vector
  pub fn der_vec(b: &[u8], tag: u8) -> Vec<&[u8]> {
      let mut vec = Vec::new();
      let mut rest = der(b, tag);
      while !rest.is_empty() {
          let (tlv, temp) = der_split(rest, false);
          vec.push(tlv);
          rest = temp;
      }
      vec
  }
  // Parse a DER encoded sequence/set with a known expected length
  pub fn der_vec_len(b: &[u8], tag: u8, length: usize) -> Vec<&[u8]> {
      let vec = der_vec(b, tag);
      assert!(vec.len() == length, "DER encoded sequence/set has invalid length!");
      vec
  }
  // Parse a sequence of DER encoded types and returns a tuple
  // The tuple contains (first type, rest of sequence/set)
  pub fn der_split(b: &[u8], value_only: bool) -> (&[u8], &[u8]) {
      assert!(b[1] < 0x84, "Did not expected length >= 2^24");
      let (start, end) = match b[1] {
          0x80 => panic!("Indefinite length encoding!"),
          0x81 => (3, 3 + b[2] as usize),
          0x82 => (4, 4 + be_bytes_to_u64(&b[2..4]) as usize),
          0x83 => (5, 5 + be_bytes_to_u64(&b[2..5]) as usize),
          _ => (2, 2 + b[1] as usize),
      };
      (&b[value_only as usize * start..end], &b[end..])
  }
}
// ======================================================
// Determinist CBOR encoding (RFC 8949)
// ======================================================
pub mod cbor {
  // CBOR encodes an unsigned interger
  pub fn cbor_uint(u: u64) -> Vec<u8> {
      cbor_type_arg(0, u)
  }
  // CBOR encodes an signed integer
  pub fn cbor_int(i: i64) -> Vec<u8> {
      if i < 0 {
          cbor_type_arg(1, -i as u64 - 1)
      } else {
          cbor_uint(i as u64)
      }
  }
  // CBOR encodes a byte string
  pub fn cbor_bytes(b: &[u8]) -> Vec<u8> {
      [&cbor_type_arg(2, b.len() as u64), b].concat()
  }
  // CBOR encodes a text string
  pub fn cbor_text(b: &[u8]) -> Vec<u8> {
      let s = std::str::from_utf8(b).unwrap(); // check that this is valid utf8
      [&cbor_type_arg(3, s.len() as u64), s.as_bytes()].concat()
  }
  // CBOR encodes an array
  pub fn cbor_array(v: &[Vec<u8>]) -> Vec<u8> {
      [cbor_type_arg(4, v.len() as u64), v.concat()].concat()
  }
  pub const CBOR_FALSE: u8 = 20;
  pub const CBOR_TRUE: u8 = 21;
  pub const CBOR_NULL: u8 = 22;
  // CBOR encodes a simple value
  pub fn cbor_simple(u: u8) -> Vec<u8> {
      cbor_type_arg(7, u as u64)
  }
  // Internal CBOR encoding helper funtion
  fn cbor_type_arg(t: u8, u: u64) -> Vec<u8> {
      let mut vec = vec![t << 5];
      if u < 24 {
          vec[0] |= u as u8;
      } else if u < u8::MAX as u64 {
          vec[0] |= 24;
          vec.extend(&(u as u8).to_be_bytes());
      } else if u < u16::MAX as u64 {
          vec[0] |= 25;
          vec.extend(&(u as u16).to_be_bytes());
      } else if u < u32::MAX as u64 {
          vec[0] |= 26;
          vec.extend(&(u as u32).to_be_bytes());
      } else {
          vec[0] |= 27;
          vec.extend(&u.to_be_bytes());
      }
      vec
  }
}



