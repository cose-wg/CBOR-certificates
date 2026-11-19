# Batch test of 2026-11-19: inputs and how to repeat it

Results: [RESULTS.md](RESULTS.md).

## Tool

- `c509` 0.6.3, commit `314b9846` of branch `c509-demo-impl-draft`
  (`cargo build --bin c509`, rustc 1.99.1).
- TLS: rustls 0.20.9 (pinned in `Cargo.lock`). The chain a host sends is
  converted as it is; it is not validated.
- The host runs were made with commit `674ca66e` and `--keep-certs`. The tables
  were then produced with `314b9846` from the certificates those runs saved.

## Inputs

| Input | Pinned by | SHA-256 |
|-------|-----------|---------|
| `tranco_V38GN_top10000.txt` (in this directory) | Tranco list ID `V38GN`, <https://tranco-list.eu/list/V38GN>; first 10,000 domains | `293721ce1fae5ee0f6f2807ffc2f93ae3854a51d8aec26f32f9903128d466a9c` |
| `crux_a67d0c8f_sample5000_seed1.txt` (in this directory) | `zakird/crux-top-lists` commit `a67d0c8f09326df09739560bc43205b4f949f8e6`, `data/global/current.csv.gz` (the October 2026 list) | `f973094ec51cf868702377650dc615d8710b432d2b82befdb9ab1ca4ce6e56e3` |
| `ccadb_2010.csv` (not stored here, 9 MB) | CCADB report "All Certificate PEMs", `NotBeforeDecade=2010`, downloaded 2026-11-18; 4,759 certificates | `82368f7843f2cda2f56c0e6017d3a252a8280b9371b472b95fbb1d02b64f5234` |
| `ccadb_2020.csv` (not stored here, 8 MB) | Same report, `NotBeforeDecade=2020`, downloaded 2026-11-18; 4,288 certificates | `9765274f978d4c85466634c79c23a204d3078f6979ec565970a1dbb72b5365e4` |
| `matter_paa_71a00964.pem` (not stored here) | `project-chip/connectedhomeip` commit `71a0096499ea451414e5a4de71b1dc80f918a81d`, `credentials/production/paa-root-certs/*.der`; 72 certificates | `7a44f4e7d1ca9f96212792e59729177cfb9594b8fe30d8b78c19aef91d33a66f` |
| `csca_master_list.pem` (not stored here) | CSCA master list published by the German BSI, `DE_ML_2026-10-01-11-50-52.ml`, downloaded 2026-11-19; 609 certificates | `7bba77a50ff1ac4f09de15d012cb174ae7323ef32c1b52828c7a1a6d18e2f32e` (ZIP as downloaded: `a0d2b448d8a2ef383c66991897c970ab2f0494173d33ef0d55195127dae08a6a`) |

The CrUX sample is 5,000 of the 982,953 distinct hosts of https origins ranked
below the top 10,000: the hosts are sorted and sampled with Python
`random.Random(1).sample()`. The sampled list is stored here so that the test
does not depend on that function.

The CCADB report is live and has no version, so a later download can differ.
The certificates that were tested are listed by SHA-256 fingerprint (of the
DER encoding, one per line, sorted) in this directory:

| File | Distinct certificates | SHA-256 of the file |
|------|----------------------|---------------------|
| `ccadb_2010_fingerprints.txt` | 4,754 | `2164ec1492886b4a9a5010c378c1b84b1841d36ccc1c9b2c295767819fa13939` |
| `ccadb_2020_fingerprints.txt` | 4,284 | `c67427838959c2acf0d8c3492e592692824d4166b39d2a01d7095454e413803b` |

These are the values of the "SHA-256 Fingerprint" column of the CCADB report,
in lower case; a certificate can be looked up by its fingerprint in the CCADB or
in a certificate transparency search.

The certificates that the hosts sent on 2026-11-19 are listed in the same way,
since a later run meets other certificates:

| File | Distinct certificates | SHA-256 of the file |
|------|----------------------|---------------------|
| `tranco_certificates_fingerprints.txt` | 7,941 | `6fae77fa5e0d8b05710f236829e702bdd50698038ffe1b34572b0de8f4c28374` |
| `crux_certificates_fingerprints.txt` | 4,894 | `2464435fe6ad4027325d6a1446f0c46c3a731e4c117ebd05cac0a8c1ffc9704c` |

The publicly trusted ones among them can be found by fingerprint in a
certificate transparency search.

The Matter roots are the production Product Attestation Authority certificates
as stored in the Matter SDK repository, which takes them from the Distributed
Compliance Ledger of the Connectivity Standards Alliance.

The CSCA master list is a list of passport-signer CA certificates of 119
countries and issuing authorities, published at
<https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html>.
It is fetched from there and is not stored or redistributed here; see that
page for its conditions of use. Its certificates were extracted from the
signed list without verifying the signature of the list.

## Fetching the inputs again

```bash
cd c509_demo_impl
./fetch_batch_lists.py --tranco 10000 --tranco-id V38GN \
    --crux 5000 --crux-commit a67d0c8f09326df09739560bc43205b4f949f8e6 --seed 1 \
    --ccadb "2010,2020" \
    --matter --matter-commit 71a0096499ea451414e5a4de71b1dc80f918a81d \
    --csca
```

This writes the inputs and a `SOURCES.txt` with the hashes to `../batch_lists/`.
The two host lists and the Matter bundle it produces are identical to the ones
used here. The CSCA master list is replaced by its publisher from time to time;
`--csca-url` selects another version.

## Running the test

```bash
cd c509_demo_impl
B=../batch_lists
R=../batch_results
./target/debug/c509 tf $B/ccadb_2020.csv           --out $R/ccadb_2020 > /dev/null
./target/debug/c509 tf $B/ccadb_2010.csv           --out $R/ccadb_2010 > /dev/null
./target/debug/c509 tf $B/matter_paa_71a00964.pem  --out $R/matter_paa > /dev/null
./target/debug/c509 tf $B/csca_master_list.pem     --out $R/csca       > /dev/null
./target/debug/c509 t $B/tranco_V38GN_top10000.txt \
    --jobs 16 --batch-size 250 --pause 2 --keep-certs --out $R/tranco > /dev/null
./target/debug/c509 t $B/crux_a67d0c8f_sample5000_seed1.txt \
    --jobs 16 --batch-size 250 --pause 2 --keep-certs --out $R/crux > /dev/null
```

The file runs give the same result every time. The host runs depend on when and
from where they are made: servers renew and change their certificates, and
reachability differs between networks. The host runs of 2026-11-19 were made
from a network in Stockholm, Sweden. `--keep-certs` saves the certificates of a
host run, and `c509 tf` on that directory repeats the conversion without new
connections.
