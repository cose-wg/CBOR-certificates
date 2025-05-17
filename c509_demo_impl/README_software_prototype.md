# Demo software for CBOR Encoded X.509 Certificates

## In brief

This version implements a critical subset of draft-ietf-cose-cbor-encoded-cert-11, using RUST.

The program outputs the encoded or decoded certificates as hex strings to standard output, but can easily be modified to converting/storing in other formats.

## Example usage

To read a DER encoded X.509 from file, encode as C509 and output to screen in hex format:
    cargo r f <der encoded certificate>

To read a plain text hex encoded CBOR C509, encode as X.509 and output to screen in hex format:
    cargo r c <cbor encoded certificate>

To read a DER encoded X.509 chain/bag from a TLS server:
    cargo r u <URL>

To read a DER encoded X.509 from file and encode as C509, encode back to X.509 and compare the results:
    cargo r l <der encoded certificate>

To read a DER encoded X.509 from URL and encode as C509, encode back to X.509 and compare the results:
    cargo r ll <URL>

To read URLs from a text list, and perform ll for each URL on the list:
    cargo r t <text list if URLs>

Run with RUST_LOG=<debug level> before `cargo` to change from the default info log level.

Please note that running the converter with options `l`, `ll` or `t` assumes there are output folders `could_convert` and `failed_convert` available for outputting log files. 

## Minimal version history

Minimal update history & known limitations:

Version 0.45, May 2025
*Added an batch mode flag to log some parsing errors without halting the program when testing a list of URLs
*Added a list of 4769 successfully tested URLs in `could_convert`, based on the top 5000 sites from `https://www.domcop.com/top-10-million-websites` which gave a reply at the last time of testing in mid May. 
The sites with certificates failing the test were:
`polskachata.cupsell.pl`, where the authorityKeyIdentifier didn't contain the by c509 required keyIdentifier field, and
`barcelona.cat`, where the Certificate Policies extension has an explicitText of type different from the c509 required utf8.

*Minor bug fixes, including issuerAltName handling

*Please note: the code is far from optimized and is not fully tested. 

Version 0.4+0.41 of the code released in July 2024
*Adding functionality to convert between C509 and X.509 format
*A few sample certs
*More bugfixes

Version 0.3 of the code released in March 2024
*A combination of a bugfix version and changes which have been made between draft-02 and draft-09

Please note: while this version contains integer encodings for all the extension names listed in the C509 Extensions Registry, not all extension values are fully cbor encoded. In those cases a warning is given during the encoding.

Version 0.2 of the code was never added to the github repo, but has been uploaded as an archive for
completeness

Version 0.1 of the code released 2021-05-25, roughly corresponding to draft-02

## Misc. resources

A few sample certificates in both X.509 and C509 are present in `test_certs`, as well as a list of URLs available as `top-5000_from_domcop.com.txt`.

`http://cbor.me/` is useful to transform between CBOR encoding and diagnostic notation.
`https://lapo.it/asn1js/` decodes DER encoded ASN.1
`https://misc.daniel-marschall.de/asn.1/oid-converter/online.php` transforms between OID dot notation and DER


## Contributing

Please report bugs or pull requests for bugfixes and improvements to the [issue tracker](https://github.com/cose-wg/CBOR-certificates/issues).
