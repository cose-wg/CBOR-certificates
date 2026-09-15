//! C509 IANA Registries — draft-ietf-cose-cbor-encoded-cert-20
//!
//! Integer IDs assigned in the IANA registries for C509 signature algorithms,
//! public key types, named curves, attribute types, extension types, and general
//! name types. Byte-array constants are pre-encoded DER OIDs and algorithm
//! identifiers for the corresponding X.509 structures.
//!
//! **Keep in sync with `conversion.rs` (Rust) and `c509_registry.h` (C) whenever
//! the draft algorithm/extension ID tables change.**
use asn1_rs::{oid, Oid, ToDer};
use crate::lder::*;

// ── Signature Algorithm Registry (Section 9.1) ───────────────────────────────
pub const SIG_RSA_V15_SHA1:    i64 = -256;
pub const SIG_ECDSA_SHA1:      i64 = -255;
pub const SIG_ECDSA_SHA256:    i64 = 0;
pub const SIG_ECDSA_SHA384:    i64 = 1;
pub const SIG_ECDSA_SHA512:    i64 = 2;
pub const SIG_ECDSA_SHAKE128:  i64 = 3;
pub const SIG_ECDSA_SHAKE256:  i64 = 4;
pub const SIG_ALG_UNSIGNED:    i64 = 5;
pub const SIG_SM2_V15_SM3:     i64 = 8;  // draft-11: was 45 in old draft
pub const SIG_ED25519:         i64 = 12;
pub const SIG_ED448:           i64 = 13;
pub const SIG_ECDHPOP_SHA256:  i64 = 14; // sa-ecdhPop-sha256-hmac-sha256 (RFC 6955)
pub const SIG_ECDHPOP_SHA384:  i64 = 15; // sa-ecdhPop-sha384-hmac-sha384 (RFC 6955)
pub const SIG_ECDHPOP_SHA512:  i64 = 16; // sa-ecdhPop-sha512-hmac-sha512 (RFC 6955)
pub const SIG_RSA_V15_SHA256:  i64 = 23;
pub const SIG_RSA_V15_SHA384:  i64 = 24;
pub const SIG_RSA_V15_SHA512:  i64 = 25;
pub const SIG_RSA_PSS_SHA256:  i64 = 26;
pub const SIG_RSA_PSS_SHA384:  i64 = 27;
pub const SIG_RSA_PSS_SHA512:  i64 = 28;
pub const SIG_RSA_PSS_SHAKE128: i64 = 29;
pub const SIG_RSA_PSS_SHAKE256: i64 = 30;

// ── Public Key Algorithm Registry (Section 9.2) ──────────────────────────────
pub const PK_RSA:           i64 = 0;
pub const PK_SECP256R:      i64 = 1;
pub const PK_SECP384R:      i64 = 2;
pub const PK_SECP521R:      i64 = 3;
pub const PK_SM2P256V1:     i64 = 6;  // draft-11: was 28 in old draft
pub const PK_X25519:        i64 = 8;
pub const PK_X448:          i64 = 9;
pub const PK_ED25519:       i64 = 12;
pub const PK_ED448:         i64 = 13;
pub const PK_BRAINPOOL256R1: i64 = 24;
pub const PK_BRAINPOOL384R1: i64 = 25;
pub const PK_BRAINPOOL512R1: i64 = 26;
pub const PK_FRP256V1:      i64 = 27;

// ── RDN Attribute Registry (Section 9.3) ─────────────────────────────────────
pub const ATT_EMAIL:               i64 = 0;
pub const ATT_COMMON_NAME:         i64 = 1;
pub const ATT_SUR_NAME:            i64 = 2;
pub const ATT_SERIAL_NUMBER:       i64 = 3;
pub const ATT_COUNTRY:             i64 = 4;
pub const ATT_LOCALITY:            i64 = 5;
pub const ATT_STATE_OR_PROVINCE:   i64 = 6;
pub const ATT_STREET_ADDRESS:      i64 = 7;
pub const ATT_ORGANIZATION:        i64 = 8;
pub const ATT_ORGANIZATION_UNIT:   i64 = 9;
pub const ATT_TITLE:               i64 = 10;
pub const ATT_BUSINESS:            i64 = 11;
pub const ATT_POSTAL_CODE:         i64 = 12;
pub const ATT_GIVEN_NAME:          i64 = 13;
pub const ATT_INITIALS:            i64 = 14;
pub const ATT_GENERATION_QUALIFIER: i64 = 15;
pub const ATT_DN_QUALIFIER:        i64 = 16;
pub const ATT_PSEUDONYM:           i64 = 17;
pub const ATT_ORG_IDENTIFIER:      i64 = 18;
pub const ATT_JUR_LOCALITY:        i64 = 19;  // draft-11: jurisdictionLocalityName
pub const ATT_JUR_STATE:           i64 = 20;  // draft-11: jurisdictionStateOrProvinceName
pub const ATT_JUR_COUNTRY:         i64 = 21;  // draft-11: jurisdictionCountryName
pub const ATT_DOMAIN_COMPONENT:    i64 = 22;
pub const ATT_NAME:                i64 = 25;
pub const ATT_TELEPHONE_NUMBER:    i64 = 26;
pub const ATT_DIR_MAN_DOMAIN_NAME: i64 = 27;
pub const ATT_USER_ID:             i64 = 28;
pub const ATT_UNSTRUCTURED_NAME:   i64 = 29;
pub const ATT_UNSTRUCTURED_ADDRESS: i64 = 30;

// ── Extension Registry (Section 9.4) ─────────────────────────────────────────
// Note: SCT List (old ID 10) was removed from the registry in draft-11.
pub const EXT_SUBJECT_KEY_ID:       u16 = 1;
pub const EXT_KEY_USAGE:            u16 = 2;
pub const EXT_SUBJECT_ALT_NAME:     u16 = 3;
pub const EXT_BASIC_CONSTRAINTS:    u16 = 4;
pub const EXT_CRL_DIST_POINTS:      u16 = 5;
pub const EXT_CERT_POLICIES:        u16 = 6;
pub const EXT_AUTH_KEY_ID:          u16 = 7;
pub const EXT_EXT_KEY_USAGE:        u16 = 8;
pub const EXT_AUTH_INFO:            u16 = 9;
pub const EXT_SUBJECT_DIRECTORY_ATTR: u16 = 24;
pub const EXT_ISSUER_ALT_NAME:      u16 = 25;
pub const EXT_NAME_CONSTRAINTS:     u16 = 26;
pub const EXT_POLICY_MAPPINGS:      u16 = 27;
pub const EXT_POLICY_CONSTRAINTS:   u16 = 28;
pub const EXT_FRESHEST_CRL:         u16 = 29;
pub const EXT_INHIBIT_ANYPOLICY:    u16 = 30;
pub const EXT_SUBJECT_INFO_ACCESS:  u16 = 31;
pub const EXT_IP_ADDR_BLOCKS:       u16 = 32;
pub const EXT_AS_IDENTIFIERS:       u16 = 33;
pub const EXT_IP_ADDR_BLOCKS_V2:    u16 = 34;
pub const EXT_AS_IDENTIFIERS_V2:    u16 = 35;
pub const EXT_OCSP_NO_CHECK:        u16 = 36;
pub const EXT_TLS_FEATURES:         u16 = 38;

// ── Extended Key Usage Registry (Section 9.5) ────────────────────────────────
pub const EKU_ANY:                    u64 = 0;
pub const EKU_TLS_SERVER:             u64 = 1;
pub const EKU_TLS_CLIENT:             u64 = 2;
pub const EKU_CODE_SIGNING:           u64 = 3;
pub const EKU_EMAIL_PROTECTION:       u64 = 4;
pub const EKU_TIME_STAMPING:          u64 = 8;
pub const EKU_OCSP_SIGNING:           u64 = 9;
pub const EKU_KERBEROS_CLIENT_AUTH:   u64 = 10;
pub const EKU_KERBEROS_KDC:           u64 = 11;
pub const EKU_SSH_CLIENT:             u64 = 12;
pub const EKU_SSH_SERVER:             u64 = 13;
pub const EKU_BUNDLE_SECURITY:        u64 = 14;
pub const EKU_CMC_CERT_AUTHORITY:     u64 = 15;
pub const EKU_CMC_REG_AUTHORITY:      u64 = 16;
pub const EKU_CMC_ARCHIVE_SERVER:     u64 = 17;
pub const EKU_CMC_KEY_GEN_AUTHORITY:  u64 = 18;

// ── Certificate Policies Registry (Section 9.6) ──────────────────────────────
pub const CP_ANY_POLICY:           i64 = 0;
pub const CP_DOMAIN_VALIDATION:    i64 = 1;
pub const CP_ORG_VALIDATION:       i64 = 2;
pub const CP_INDIVIDUAL_VALIDATION: i64 = 3;
pub const CP_EXTENDED_VALIDATION:  i64 = 4;
pub const CP_RESOURCE_PKI:         i64 = 7;
pub const CP_RESOURCE_PKI_ALT:     i64 = 8;
// RSP roles — draft-11: IDs 24-38 (was 10-17 in old draft).
// The old OIDs (2.23.146.1.2.1.0 through .7) are now the v2 entries (odd IDs 25,27,29,31,33,35,37).
// The v1 entries (even IDs 26,28,30,32,34,36,38) have new OIDs not yet widely deployed.
pub const CP_RSP_CI:               i64 = 24;  // Certificate Issuer
pub const CP_RSP_EUICC_V2:         i64 = 25;  // eUICC (v2, OID 2.23.146.1.2.1.1)
pub const CP_RSP_EUICC:            i64 = 26;  // eUICC (v1, new OID — see draft Table 19)
pub const CP_RSP_EUM_V2:           i64 = 27;  // eUICC Manufacturer (v2, OID 2.23.146.1.2.1.2)
pub const CP_RSP_EUM:              i64 = 28;  // eUICC Manufacturer (v1, new OID)
pub const CP_RSP_DP_TLS_V2:        i64 = 29;  // SM-DP+ TLS (v2, OID 2.23.146.1.2.1.3)
pub const CP_RSP_DP_TLS:           i64 = 30;  // SM-DP+ TLS (v1, new OID)
pub const CP_RSP_DP_AUTH_V2:       i64 = 31;  // SM-DP+ Auth (v2, OID 2.23.146.1.2.1.4)
pub const CP_RSP_DP_AUTH:          i64 = 32;  // SM-DP+ Auth (v1, new OID)
pub const CP_RSP_DP_PB_V2:         i64 = 33;  // SM-DP+ Profile Binding (v2, OID 2.23.146.1.2.1.5)
pub const CP_RSP_DP_PB:            i64 = 34;  // SM-DP+ Profile Binding (v1, new OID)
pub const CP_RSP_DS_TLS_V2:        i64 = 35;  // SM-DS TLS (v2, OID 2.23.146.1.2.1.6)
pub const CP_RSP_DS_TLS:           i64 = 36;  // SM-DS TLS (v1, new OID)
pub const CP_RSP_DS_AUTH_V2:       i64 = 37;  // SM-DS Auth (v2, OID 2.23.146.1.2.1.7)
pub const CP_RSP_DS_AUTH:          i64 = 38;  // SM-DS Auth (v1, new OID)

// ── Policy Qualifier Registry (Section 9.7) ──────────────────────────────────
pub const PQ_CPS:     i64 = 1;
pub const PQ_UNOTICE: i64 = 2;

// ── Information Access Registry (Section 9.8) ────────────────────────────────
pub const INFO_OCSP:          i64 = 1;
pub const INFO_CA_ISSUERS:    i64 = 2;
pub const INFO_TIME_STAMPING: i64 = 3;
pub const INFO_CA_REPOSITORY: i64 = 5;
pub const INFO_RPKI_MANIFEST: i64 = 10;
pub const INFO_SIGNED_OBJECT: i64 = 11;
pub const INFO_RPKI_NOTIFY:   i64 = 13;

// ── OID constants ─────────────────────────────────────────────────────────────
// Signature algorithm OIDs
pub const SIG_RSA_V15_SHA1_OID:    Oid<'static> = oid!(1.2.840.113549.1.1.5);
pub const SIG_ECDSA_SHA1_OID:      Oid<'static> = oid!(1.2.840.10045.4.1);
pub const SIG_ECDSA_SHA256_OID:    Oid<'static> = oid!(1.2.840.10045.4.3.2);
pub const SIG_ECDSA_SHA384_OID:    Oid<'static> = oid!(1.2.840.10045.4.3.3);
pub const SIG_ECDSA_SHA512_OID:    Oid<'static> = oid!(1.2.840.10045.4.3.4);
pub const SIG_ECDSA_SHAKE128_OID:  Oid<'static> = oid!(1.3.6.1.5.5.7.6.32);
pub const SIG_ECDSA_SHAKE256_OID:  Oid<'static> = oid!(1.3.6.1.5.5.7.6.33);
pub const SIG_SM2_V15_SM3_OID:     Oid<'static> = oid!(1.2.156.10197.1.501);
pub const SIG_ED25519_OID:         Oid<'static> = oid!(1.3.101.112);
pub const SIG_ED448_OID:           Oid<'static> = oid!(1.3.101.113);
pub const SIG_ALG_UNSIGNED_OID:    Oid<'static> = oid!(1.3.6.1.5.5.7.6.36); // id-alg-unsigned
pub const SIG_RSA_V15_SHA256_OID:  Oid<'static> = oid!(1.2.840.113549.1.1.11);
pub const SIG_RSA_V15_SHA384_OID:  Oid<'static> = oid!(1.2.840.113549.1.1.12);
pub const SIG_RSA_V15_SHA512_OID:  Oid<'static> = oid!(1.2.840.113549.1.1.13);
pub const SIG_RSA_PSS_OID:         Oid<'static> = oid!(1.2.840.113549.1.1.10);
pub const SIG_RSA_PSS_SHA256_OID:  Oid<'static> = oid!(1.2.840.113549.1.1.10); // PSS OID, hash in params
pub const SIG_RSA_PSS_SHA384_OID:  Oid<'static> = oid!(1.2.840.113549.1.1.10); // PSS OID, hash in params
pub const SIG_RSA_PSS_SHA512_OID:  Oid<'static> = oid!(1.2.840.113549.1.1.10); // PSS OID, hash in params
pub const SIG_RSA_PSS_SHAKE128_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.6.30);
pub const SIG_RSA_PSS_SHAKE256_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.6.31);
// DH-PoP (Diffie-Hellman proof-of-possession, RFC 6955 / C509 §9.1 Table 3)
pub const SIG_ECDHPOP_SHA256_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.6.26);
pub const SIG_ECDHPOP_SHA384_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.6.27);
pub const SIG_ECDHPOP_SHA512_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.6.28);
// PrivateKeyPossessionStatement attribute OID (RFC 9883 / C509 §7.2 attr type 2)
pub const PRIV_KEY_POSS_STMT_OID_BYTES: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xAC, 0x60, 0x02, 0x01];
pub const HASH_SHA256_OID:         Oid<'static> = oid!(2.16.840.1.101.3.4.2.1);
pub const HASH_SHA384_OID:         Oid<'static> = oid!(2.16.840.1.101.3.4.2.2);
pub const HASH_SHA512_OID:         Oid<'static> = oid!(2.16.840.1.101.3.4.2.3);
pub const MGF1_OID:                Oid<'static> = oid!(1.2.840.113549.1.1.8);

// Public key algorithm OIDs
pub const PK_RSA_OID:              Oid<'static> = oid!(1.2.840.113549.1.1.1);
pub const PK_EC_OID:               Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey (shared)
pub const PK_SECP256R_OID:         Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_SECP256R_PARAM_OID:   Oid<'static> = oid!(1.2.840.10045.3.1.7);
pub const PK_SECP384R_OID:         Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_SECP384R_PARAM_OID:   Oid<'static> = oid!(1.3.132.0.34);
pub const PK_SECP521R_OID:         Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_SECP521R_PARAM_OID:   Oid<'static> = oid!(1.3.132.0.35);
pub const PK_SM2P256V1_OID:        Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_SM2P256V1_PARAM_OID:  Oid<'static> = oid!(1.2.156.10197.1.301);
pub const PK_X25519_OID:           Oid<'static> = oid!(1.3.101.110);
pub const PK_X448_OID:             Oid<'static> = oid!(1.3.101.111);
pub const PK_ED25519_OID:          Oid<'static> = oid!(1.3.101.112);
pub const PK_ED448_OID:            Oid<'static> = oid!(1.3.101.113);
pub const PK_BRAINPOOL256R1_OID:   Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_BRAINPOOL256R1_PARAM_OID: Oid<'static> = oid!(1.3.36.3.3.2.8.1.1.7);
pub const PK_BRAINPOOL384R1_OID:   Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_BRAINPOOL384R1_PARAM_OID: Oid<'static> = oid!(1.3.36.3.3.2.8.1.1.11);
pub const PK_BRAINPOOL512R1_OID:   Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_BRAINPOOL512R1_PARAM_OID: Oid<'static> = oid!(1.3.36.3.3.2.8.1.1.13);
pub const PK_FRP256V1_OID:         Oid<'static> = oid!(1.2.840.10045.2.1); // ecPublicKey
pub const PK_FRP256V1_PARAM_OID:   Oid<'static> = oid!(1.2.250.1.223.101.256.1);

// Attribute OIDs
pub const ATT_EMAIL_OID:              Oid<'static> = oid!(1.2.840.113549.1.9.1);
pub const ATT_COMMON_NAME_OID:        Oid<'static> = oid!(2.5.4.3);
pub const ATT_SUR_NAME_OID:           Oid<'static> = oid!(2.5.4.4);
pub const ATT_SERIAL_NUMBER_OID:      Oid<'static> = oid!(2.5.4.5);
pub const ATT_COUNTRY_OID:            Oid<'static> = oid!(2.5.4.6);
pub const ATT_LOCALITY_OID:           Oid<'static> = oid!(2.5.4.7);
pub const ATT_STATE_OR_PROVINCE_OID:  Oid<'static> = oid!(2.5.4.8);
pub const ATT_STREET_ADDRESS_OID:     Oid<'static> = oid!(2.5.4.9);
pub const ATT_ORGANIZATION_OID:       Oid<'static> = oid!(2.5.4.10);
pub const ATT_ORGANIZATION_UNIT_OID:  Oid<'static> = oid!(2.5.4.11);
pub const ATT_TITLE_OID:              Oid<'static> = oid!(2.5.4.12);
pub const ATT_BUSINESS_OID:           Oid<'static> = oid!(2.5.4.15);
pub const ATT_POSTAL_CODE_OID:        Oid<'static> = oid!(2.5.4.17);
pub const ATT_GIVEN_NAME_OID:         Oid<'static> = oid!(2.5.4.42);
pub const ATT_INITIALS_OID:           Oid<'static> = oid!(2.5.4.43);
pub const ATT_GENERATION_QUALIFIER_OID: Oid<'static> = oid!(2.5.4.44);
pub const ATT_DN_QUALIFIER_OID:       Oid<'static> = oid!(2.5.4.46);
pub const ATT_PSEUDONYM_OID:          Oid<'static> = oid!(2.5.4.65);
pub const ATT_ORG_ID_OID:             Oid<'static> = oid!(2.5.4.97);
pub const ATT_INC_LOCALITY_OID:       Oid<'static> = oid!(1.3.6.1.4.1.311.60.2.1.1);
pub const ATT_INC_STATE_OID:          Oid<'static> = oid!(1.3.6.1.4.1.311.60.2.1.2);
pub const ATT_INC_COUNTRY_OID:        Oid<'static> = oid!(1.3.6.1.4.1.311.60.2.1.3);
pub const ATT_DOMAIN_COMPONENT_OID:   Oid<'static> = oid!(0.9.2342.19200300.100.1.25);
pub const ATT_NAME_OID:               Oid<'static> = oid!(2.5.4.41);
pub const ATT_TELEPHONE_NUMBER_OID:   Oid<'static> = oid!(2.5.4.20);
pub const ATT_DIR_MAN_DOMAIN_NAME_OID: Oid<'static> = oid!(2.5.4.54);
pub const ATT_USER_ID_OID:            Oid<'static> = oid!(0.9.2342.19200300.100.1.1);
pub const ATT_UNSTRUCTURED_NAME_OID:  Oid<'static> = oid!(1.2.840.113549.1.9.2);
pub const ATT_UNSTRUCTURED_ADDRESS_OID: Oid<'static> = oid!(1.2.840.113549.1.9.8);

// Extension OIDs
pub const EXT_SUBJECT_KEY_ID_OID:    Oid<'static> = oid!(2.5.29.14);
pub const EXT_KEY_USAGE_OID:         Oid<'static> = oid!(2.5.29.15);
pub const EXT_SUBJECT_ALT_NAME_OID:  Oid<'static> = oid!(2.5.29.17);
pub const EXT_ISSUER_ALT_NAME_OID:   Oid<'static> = oid!(2.5.29.18);
pub const EXT_BASIC_CONSTRAINTS_OID: Oid<'static> = oid!(2.5.29.19);
pub const EXT_CRL_DIST_POINTS_OID:   Oid<'static> = oid!(2.5.29.31);
pub const EXT_CERT_POLICIES_OID:     Oid<'static> = oid!(2.5.29.32);
pub const EXT_POLICY_MAPPINGS_OID:   Oid<'static> = oid!(2.5.29.33);
pub const EXT_AUTH_KEY_ID_OID:       Oid<'static> = oid!(2.5.29.35);
pub const EXT_POLICY_CONSTRAINTS_OID: Oid<'static> = oid!(2.5.29.36);
pub const EXT_EXT_KEY_USAGE_OID:     Oid<'static> = oid!(2.5.29.37);
pub const EXT_FRESHEST_CRL_OID:      Oid<'static> = oid!(2.5.29.46);
pub const EXT_INHIBIT_ANYPOLICY_OID: Oid<'static> = oid!(2.5.29.54);
pub const EXT_SUBJECT_DIRECTORY_ATTR_OID: Oid<'static> = oid!(2.5.29.9);
pub const EXT_NAME_CONSTRAINTS_OID:  Oid<'static> = oid!(2.5.29.30);
pub const EXT_AUTH_INFO_OID:         Oid<'static> = oid!(1.3.6.1.5.5.7.1.1);
pub const EXT_SUBJECT_INFO_ACCESS_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.1.11);
pub const EXT_IP_ADDR_BLOCKS_OID:    Oid<'static> = oid!(1.3.6.1.5.5.7.1.7);
pub const EXT_AS_IDENTIFIERS_OID:    Oid<'static> = oid!(1.3.6.1.5.5.7.1.8);
pub const EXT_IP_ADDR_BLOCKS_V2_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.1.28);
pub const EXT_AS_IDENTIFIERS_V2_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.1.29);
pub const EXT_OCSP_NO_CHECK_OID:     Oid<'static> = oid!(1.3.6.1.5.5.7.48.1.5);
pub const EXT_TLS_FEATURES_OID:      Oid<'static> = oid!(1.3.6.1.5.5.7.1.24);
// SCT List OID kept for fallback raw-OID encoding (ext no longer registered in draft-11)
pub const EXT_SCT_LIST_OID:          Oid<'static> = oid!(1.3.6.1.4.1.11129.2.4.2);

// Certificate policy OIDs
pub const CP_ANY_POLICY_OID:         Oid<'static> = oid!(2.5.29.32.0);
pub const CP_DOMAIN_VALIDATION_OID:  Oid<'static> = oid!(2.23.140.1.2.1);
pub const CP_ORG_VALIDATION_OID:     Oid<'static> = oid!(2.23.140.1.2.2);
pub const CP_INDIVIDUAL_VALIDATION_OID: Oid<'static> = oid!(2.23.140.1.2.3);
pub const CP_EXTENDED_VALIDATION_OID: Oid<'static> = oid!(2.23.140.1.1);
pub const CP_RESOURCE_PKI_OID:       Oid<'static> = oid!(1.3.6.1.5.5.7.14.2);
pub const CP_RESOURCE_PKI_ALT_OID:   Oid<'static> = oid!(1.3.6.1.5.5.7.14.3);
// RSP OIDs: 2.23.146.1.2.1.{0-7} — draft-11 maps these to the v2 entries (IDs 24,25,27,29,31,33,35,37).
// The v1 entries (IDs 26,28,30,32,34,36,38) use new OID sub-arcs not yet common in the wild.

// Policy qualifier OIDs
pub const PQ_CPS_OID:     Oid<'static> = oid!(1.3.6.1.5.5.7.2.1);
pub const PQ_UNOTICE_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.2.2);

// Information access OIDs
pub const INFO_OCSP_OID:          Oid<'static> = oid!(1.3.6.1.5.5.7.48.1);
pub const INFO_CA_ISSUERS_OID:    Oid<'static> = oid!(1.3.6.1.5.5.7.48.2);
pub const INFO_TIME_STAMPING_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.48.3);
pub const INFO_CA_REPOSITORY_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.48.5);
pub const INFO_RPKI_MANIFEST_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.48.10);
pub const INFO_SIGNED_OBJECT_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.48.11);
pub const INFO_RPKI_NOTIFY_OID:   Oid<'static> = oid!(1.3.6.1.5.5.7.48.13);

// Extended key usage OIDs
pub const EKU_ANY_OID:                     Oid<'static> = oid!(2.5.29.37.0);
pub const EKU_TLS_SERVER_OID:              Oid<'static> = oid!(1.3.6.1.5.5.7.3.1);
pub const EKU_TLS_CLIENT_OID:              Oid<'static> = oid!(1.3.6.1.5.5.7.3.2);
pub const EKU_CODE_SIGNING_OID:            Oid<'static> = oid!(1.3.6.1.5.5.7.3.3);
pub const EKU_EMAIL_PROTECTION_OID:        Oid<'static> = oid!(1.3.6.1.5.5.7.3.4);
pub const EKU_TIME_STAMPING_OID:           Oid<'static> = oid!(1.3.6.1.5.5.7.3.8);
pub const EKU_OCSP_SIGNING_OID:            Oid<'static> = oid!(1.3.6.1.5.5.7.3.9);
pub const EKU_KERBEROS_CLIENT_AUTH_OID:    Oid<'static> = oid!(1.3.6.1.5.2.3.4);
pub const EKU_KERBEROS_KDC_OID:            Oid<'static> = oid!(1.3.6.1.5.2.3.5);
pub const EKU_SSH_CLIENT_OID:              Oid<'static> = oid!(1.3.6.1.5.5.7.3.21);
pub const EKU_SSH_SERVER_OID:              Oid<'static> = oid!(1.3.6.1.5.5.7.3.22);
pub const EKU_BUNDLE_SECURITY_OID:         Oid<'static> = oid!(1.3.6.1.5.5.7.3.35);
pub const EKU_CMC_CERT_AUTHORITY_OID:      Oid<'static> = oid!(1.3.6.1.5.5.7.3.27);
pub const EKU_CMC_REG_AUTHORITY_OID:       Oid<'static> = oid!(1.3.6.1.5.5.7.3.28);
pub const EKU_CMC_ARCHIVE_SERVER_OID:      Oid<'static> = oid!(1.3.6.1.5.5.7.3.29);
pub const EKU_CMC_KEY_GEN_AUTHORITY_OID:   Oid<'static> = oid!(1.3.6.1.5.5.7.3.32);

// Other name OIDs (for GeneralName)
pub const OTHER_NAME_HW_MODULE_OID:    Oid<'static> = oid!(1.3.6.1.5.5.7.8.4);
pub const OTHER_NAME_PERMANENT_ID_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.8.9);
pub const OTHER_NAME_SMTP_UTF8_MAILBOX_OID: Oid<'static> = oid!(1.3.6.1.5.5.7.8.12);
pub const OTHER_NAME_USER_NOTICE_OID:       Oid<'static> = oid!(1.3.6.1.5.5.7.8.11);

// ── Lookup functions ──────────────────────────────────────────────────────────

/// Maps a DER-encoded signature AlgorithmIdentifier to a C509 signature algorithm ID.
pub fn sig_map(alg_id: &[u8]) -> Option<i64> {
    let inner = lder(alg_id, ASN1_SEQ);
    match inner {
        // Ed25519 / Ed448 — OID only, no params
        [0x06, 0x03, 0x2B, 0x65, 0x70, ..] => Some(SIG_ED25519),
        [0x06, 0x03, 0x2B, 0x65, 0x71, ..] => Some(SIG_ED448),
        // ECDSA with hash
        [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, tail @ ..] => match tail.first() {
            Some(0x01) => Some(SIG_ECDSA_SHA1),
            Some(0x02) => Some(SIG_ECDSA_SHA256),
            Some(0x03) => Some(SIG_ECDSA_SHA384),
            Some(0x04) => Some(SIG_ECDSA_SHA512),
            _ => None,
        },
        // ECDSA-SHAKE (.20=32, .21=33), RSA-PSS-SHAKE (.1E=30, .1F=31),
        // id-alg-unsigned (.24=36, C509 ID 5), and ecdhPop (.1A=26/14, .1B=27/15, .1C=28/16).
        [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, tail @ ..] => match tail.first() {
            Some(0x20) => Some(SIG_ECDSA_SHAKE128),
            Some(0x21) => Some(SIG_ECDSA_SHAKE256),
            Some(0x24) => Some(SIG_ALG_UNSIGNED),
            Some(0x1E) => Some(SIG_RSA_PSS_SHAKE128),
            Some(0x1F) => Some(SIG_RSA_PSS_SHAKE256),
            Some(0x1A) => Some(SIG_ECDHPOP_SHA256),
            Some(0x1B) => Some(SIG_ECDHPOP_SHA384),
            Some(0x1C) => Some(SIG_ECDHPOP_SHA512),
            _ => None,
        },
        // RSA PKCS#1 v1.5 and PSS
        [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, tail @ ..] => match tail {
            [0x05, 0x05, 0x00, ..] => Some(SIG_RSA_V15_SHA1),
            [0x0B, 0x05, 0x00, ..] => Some(SIG_RSA_V15_SHA256),
            [0x0C, 0x05, 0x00, ..] => Some(SIG_RSA_V15_SHA384),
            [0x0D, 0x05, 0x00, ..] => Some(SIG_RSA_V15_SHA512),
            // RSA-PSS: OID 1.2.840.113549.1.1.10 — inspect hash inside params
            [0x0A, ..] => {
                let hash_prefix = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];
                inner.windows(hash_prefix.len())
                    .position(|w| w == hash_prefix)
                    .and_then(|pos| inner.get(pos + hash_prefix.len()))
                    .and_then(|&h| match h {
                        0x01 => Some(SIG_RSA_PSS_SHA256),
                        0x02 => Some(SIG_RSA_PSS_SHA384),
                        0x03 => Some(SIG_RSA_PSS_SHA512),
                        _ => None,
                    })
            }
            _ => None,
        },
        // ecdsa-with-SHA1: OID 1.2.840.10045.4.1 (7 OID bytes)
        [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01, ..] => Some(SIG_ECDSA_SHA1),
        // SM2 with SM3: OID 1.2.156.10197.1.501; 501 = 3*128+117 = 0x83 0x75
        [0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75, ..] => Some(SIG_SM2_V15_SM3),
        _ => None,
    }
}

/// Maps a DER-encoded SubjectPublicKeyInfo AlgorithmIdentifier to a C509 public key type ID.
pub fn pk_map(alg_id: &[u8]) -> Option<i64> {
    let components = lder_vec(alg_id, ASN1_SEQ);
    if components.is_empty() { return None; }
    let oid = lder(components[0], ASN1_OID);
    match oid {
        [0x2B, 0x65, 0x6E] => Some(PK_X25519),
        [0x2B, 0x65, 0x6F] => Some(PK_X448),
        [0x2B, 0x65, 0x70] => Some(PK_ED25519),
        [0x2B, 0x65, 0x71] => Some(PK_ED448),
        // rsaEncryption
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] => Some(PK_RSA),
        // ecPublicKey — distinguish by curve OID
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] => {
            if components.len() < 2 { return None; }
            let curve = lder(components[1], ASN1_OID);
            match curve {
                [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => Some(PK_SECP256R),
                [0x2B, 0x81, 0x04, 0x00, 0x22]                    => Some(PK_SECP384R),
                [0x2B, 0x81, 0x04, 0x00, 0x23]                    => Some(PK_SECP521R),
                [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => Some(PK_BRAINPOOL256R1),
                [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B] => Some(PK_BRAINPOOL384R1),
                [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D] => Some(PK_BRAINPOOL512R1),
                [0x2A, 0x81, 0x7A, 0x01, 0x81, 0x5F, 0x65, 0x82, 0x00, 0x01] => Some(PK_FRP256V1),
                [0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D]  => Some(PK_SM2P256V1),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Maps a DER-encoded attribute OID (value bytes, no tag/length) to a C509 attribute ID.
pub fn att_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x55, 0x04, rest @ ..] => match rest {
            [0x03] => Some(ATT_COMMON_NAME),
            [0x04] => Some(ATT_SUR_NAME),
            [0x05] => Some(ATT_SERIAL_NUMBER),
            [0x06] => Some(ATT_COUNTRY),
            [0x07] => Some(ATT_LOCALITY),
            [0x08] => Some(ATT_STATE_OR_PROVINCE),
            [0x09] => Some(ATT_STREET_ADDRESS),
            [0x0A] => Some(ATT_ORGANIZATION),
            [0x0B] => Some(ATT_ORGANIZATION_UNIT),
            [0x0C] => Some(ATT_TITLE),
            [0x0F] => Some(ATT_BUSINESS),
            [0x11] => Some(ATT_POSTAL_CODE),
            [0x14] => Some(ATT_TELEPHONE_NUMBER),
            [0x29] => Some(ATT_NAME),
            [0x2A] => Some(ATT_GIVEN_NAME),
            [0x2B] => Some(ATT_INITIALS),
            [0x2C] => Some(ATT_GENERATION_QUALIFIER),
            [0x2E] => Some(ATT_DN_QUALIFIER),
            [0x36] => Some(ATT_DIR_MAN_DOMAIN_NAME),
            [0x41] => Some(ATT_PSEUDONYM),
            [0x61] => Some(ATT_ORG_IDENTIFIER),
            _ => None,
        },
        // emailAddress
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => Some(ATT_EMAIL),
        // userId / domainComponent (LDAP)
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, rest @ ..] => match rest {
            [0x01] => Some(ATT_USER_ID),
            [0x19] => Some(ATT_DOMAIN_COMPONENT),
            _ => None,
        },
        // unstructuredName / unstructuredAddress (PKCS#9)
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, rest @ ..] => match rest {
            [0x02] => Some(ATT_UNSTRUCTURED_NAME),
            [0x08] => Some(ATT_UNSTRUCTURED_ADDRESS),
            _ => None,
        },
        // jurisdictionLocality/State/Country (Microsoft EV, OID 1.3.6.1.4.1.311.60.2.1.x)
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, rest @ ..] => match rest {
            [0x01] => Some(ATT_JUR_LOCALITY),
            [0x02] => Some(ATT_JUR_STATE),
            [0x03] => Some(ATT_JUR_COUNTRY),
            _ => None,
        },
        _ => None,
    }
}

/// Maps a DER-encoded extension OID (value bytes) to a C509 extension ID.
/// SCT List (old ID 10) is not registered in draft-11 and returns None.
pub fn ext_map(oid: &[u8]) -> Option<u16> {
    match oid {
        [0x55, 0x1D, rest @ ..] => match rest {
            [0x09] => Some(EXT_SUBJECT_DIRECTORY_ATTR),
            [0x0E] => Some(EXT_SUBJECT_KEY_ID),
            [0x0F] => Some(EXT_KEY_USAGE),
            [0x11] => Some(EXT_SUBJECT_ALT_NAME),
            [0x12] => Some(EXT_ISSUER_ALT_NAME),
            [0x13] => Some(EXT_BASIC_CONSTRAINTS),
            [0x1E] => Some(EXT_NAME_CONSTRAINTS),
            [0x1F] => Some(EXT_CRL_DIST_POINTS),
            [0x20] => Some(EXT_CERT_POLICIES),
            [0x21] => Some(EXT_POLICY_MAPPINGS),
            [0x23] => Some(EXT_AUTH_KEY_ID),
            [0x24] => Some(EXT_POLICY_CONSTRAINTS),
            [0x25] => Some(EXT_EXT_KEY_USAGE),
            [0x2E] => Some(EXT_FRESHEST_CRL),
            [0x36] => Some(EXT_INHIBIT_ANYPOLICY),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, rest @ ..] => match rest {
            [0x01] => Some(EXT_AUTH_INFO),
            [0x07] => Some(EXT_IP_ADDR_BLOCKS),
            [0x08] => Some(EXT_AS_IDENTIFIERS),
            [0x0B] => Some(EXT_SUBJECT_INFO_ACCESS),
            [0x18] => Some(EXT_TLS_FEATURES),
            [0x1C] => Some(EXT_IP_ADDR_BLOCKS_V2),
            [0x1D] => Some(EXT_AS_IDENTIFIERS_V2),
            _ => None,
        },
        // OCSP No Check: 1.3.6.1.5.5.7.48.1.5
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05] => Some(EXT_OCSP_NO_CHECK),
        _ => None,
    }
}

/// Maps a DER-encoded certificate policy OID (value bytes) to a C509 policy ID.
pub fn cp_map(oid: &[u8]) -> Option<i64> {
    match oid {
        // anyPolicy
        [0x55, 0x1D, 0x20, 0x00] => Some(CP_ANY_POLICY),
        // CA/Browser Forum (OID arc 2.23.140.1.x)
        [0x67, 0x81, 0x0C, 0x01, rest @ ..] => match rest {
            [0x01]       => Some(CP_EXTENDED_VALIDATION),
            [0x02, 0x01] => Some(CP_DOMAIN_VALIDATION),
            [0x02, 0x02] => Some(CP_ORG_VALIDATION),
            [0x02, 0x03] => Some(CP_INDIVIDUAL_VALIDATION),
            _ => None,
        },
        // RPKI (OID arc 1.3.6.1.5.5.7.14.x)
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0E, rest @ ..] => match rest {
            [0x02] => Some(CP_RESOURCE_PKI),
            [0x03] => Some(CP_RESOURCE_PKI_ALT),
            _ => None,
        },
        // RSP roles (OID arc 2.23.146.1.2.1.x) — draft-11: these map to the v2 entries (odd IDs).
        // CI (arc .0) keeps ID 24. All others (.1 through .7) become the v2 variants.
        [0x67, 0x81, 0x12, 0x01, 0x02, 0x01, rest @ ..] => match rest {
            [0x00] => Some(CP_RSP_CI),
            [0x01] => Some(CP_RSP_EUICC_V2),
            [0x02] => Some(CP_RSP_EUM_V2),
            [0x03] => Some(CP_RSP_DP_TLS_V2),
            [0x04] => Some(CP_RSP_DP_AUTH_V2),
            [0x05] => Some(CP_RSP_DP_PB_V2),
            [0x06] => Some(CP_RSP_DS_TLS_V2),
            [0x07] => Some(CP_RSP_DS_AUTH_V2),
            _ => None,
        },
        _ => None,
    }
}

/// Maps a DER-encoded policy qualifier OID (value bytes) to a C509 qualifier ID.
pub fn pq_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, rest @ ..] => match rest {
            [0x01] => Some(PQ_CPS),
            [0x02] => Some(PQ_UNOTICE),
            _ => None,
        },
        _ => None,
    }
}

/// Maps a DER-encoded EKU OID (value bytes) to a C509 EKU ID.
pub fn eku_map(oid: &[u8]) -> Option<u64> {
    match oid {
        // anyExtendedKeyUsage
        [0x55, 0x1D, 0x25, 0x00] => Some(EKU_ANY),
        // id-kp (OID arc 1.3.6.1.5.5.7.3.x)
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, rest @ ..] => match rest {
            [0x01] => Some(EKU_TLS_SERVER),
            [0x02] => Some(EKU_TLS_CLIENT),
            [0x03] => Some(EKU_CODE_SIGNING),
            [0x04] => Some(EKU_EMAIL_PROTECTION),
            [0x08] => Some(EKU_TIME_STAMPING),
            [0x09] => Some(EKU_OCSP_SIGNING),
            [0x15] => Some(EKU_SSH_CLIENT),
            [0x16] => Some(EKU_SSH_SERVER),
            [0x1B] => Some(EKU_CMC_CERT_AUTHORITY),
            [0x1C] => Some(EKU_CMC_REG_AUTHORITY),
            [0x1D] => Some(EKU_CMC_ARCHIVE_SERVER),
            [0x20] => Some(EKU_CMC_KEY_GEN_AUTHORITY),
            [0x23] => Some(EKU_BUNDLE_SECURITY),
            _ => None,
        },
        // Kerberos PKINIT (OID arc 1.3.6.1.5.2.3.x)
        [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, rest @ ..] => match rest {
            [0x04] => Some(EKU_KERBEROS_CLIENT_AUTH),
            [0x05] => Some(EKU_KERBEROS_KDC),
            _ => None,
        },
        _ => None,
    }
}

/// Maps a DER-encoded information access OID (value bytes) to a C509 info access ID.
pub fn info_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, rest @ ..] => match rest {
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

/// Maps a C509 certificate policy ID back to its DER-encoded OID (for C509→X.509 decoding).
pub fn map_cert_policy_id_to_oid(id: i64) -> Vec<u8> {
    match id {
        CP_ANY_POLICY             => CP_ANY_POLICY_OID.to_der_vec().unwrap(),
        CP_DOMAIN_VALIDATION      => CP_DOMAIN_VALIDATION_OID.to_der_vec().unwrap(),
        CP_ORG_VALIDATION         => CP_ORG_VALIDATION_OID.to_der_vec().unwrap(),
        CP_INDIVIDUAL_VALIDATION  => CP_INDIVIDUAL_VALIDATION_OID.to_der_vec().unwrap(),
        CP_EXTENDED_VALIDATION    => CP_EXTENDED_VALIDATION_OID.to_der_vec().unwrap(),
        CP_RESOURCE_PKI           => CP_RESOURCE_PKI_OID.to_der_vec().unwrap(),
        CP_RESOURCE_PKI_ALT       => CP_RESOURCE_PKI_ALT_OID.to_der_vec().unwrap(),
        // RSP v2 entries use the old well-known OID sub-arcs
        CP_RSP_CI                 => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x00],
        CP_RSP_EUICC_V2           => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x01],
        CP_RSP_EUM_V2             => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x02],
        CP_RSP_DP_TLS_V2          => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x03],
        CP_RSP_DP_AUTH_V2         => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x04],
        CP_RSP_DP_PB_V2           => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x05],
        CP_RSP_DS_TLS_V2          => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x06],
        CP_RSP_DS_AUTH_V2         => vec![0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x07],
        // TODO: v1 RSP OIDs (IDs 26,28,30,32,34,36,38) use new sub-arcs from draft-11 Table 19
        _ => panic!("Unknown certificate policy ID: {}", id),
    }
}
