#!/usr/bin/env python3
"""Fetch the inputs for the batch test (`c509 t` / `c509 tf`).

Writes into the output directory:

  tranco_<ID>_top<N>.txt        the first N domains of a Tranco list
  crux_<COMMIT>_sample<N>_seed<S>.txt
                                N hosts sampled from the CrUX top-million origins
                                outside the top 10,000 (the long tail)
  ccadb_<DECADE>.csv            CA certificates (PEM in CSV) from the CCADB
  matter_paa_<COMMIT>.pem       with --matter: the Matter production attestation
                                root certificates (PAA)
  csca_master_list.pem          with --csca: the certificates of a CSCA master list
  SOURCES.txt                   for every input: the URL it was fetched from, the
                                identifier that pins it, the SHA-256 of the
                                download and of the derived list, and the command
                                that fetches the same inputs again

Sources:
  Tranco   https://tranco-list.eu          research ranking; each list has a
                                           permanent ID
  CrUX     https://github.com/zakird/crux-top-lists
                                           Chrome top-million origins, ranked in
                                           buckets (1000, 10000, 100000, 1000000);
                                           pinned by the commit of that repository
  CCADB    https://www.ccadb.org/resources root and intermediate CA certificates
                                           known to the browser root programmes
  Matter   https://github.com/project-chip/connectedhomeip
                                           credentials/production/paa-root-certs,
                                           a snapshot of the roots registered in the
                                           CSA Distributed Compliance Ledger; pinned
                                           by the commit of that repository
  CSCA     https://www.bsi.bund.de         master list of passport-signer (CSCA)
                                           certificates published by the German BSI.
                                           The list is not redistributed; see the
                                           conditions of use on the BSI page. Its
                                           signature is not verified here: the
                                           certificates are only extracted.

Without --tranco-id / --crux-commit the current Tranco list and the latest CrUX
commit are used and recorded. With them, the same host lists are produced again.
The CCADB report is live and has no version: its SHA-256 is recorded, and the
batch test CSV lists the SHA-256 fingerprint of every certificate tested.

Only the Python standard library is used.

Usage:
  ./fetch_batch_lists.py [--out DIR] [--tranco N] [--tranco-id ID]
                         [--crux N] [--crux-commit SHA] [--seed S]
                         [--ccadb DECADE[,DECADE...]]
                         [--matter] [--matter-commit SHA] [--csca] [--csca-url URL]
"""

import argparse
import base64
import csv
import datetime
import gzip
import hashlib
import io
import json
import os
import random
import urllib.request
import zipfile

TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_LIST_URL = "https://tranco-list.eu/download/{id}/{n}"
CRUX_PATH = "data/global/current.csv.gz"
CRUX_COMMITS_URL = "https://api.github.com/repos/zakird/crux-top-lists/commits?path=%s&per_page=1" % CRUX_PATH
CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/{commit}/" + CRUX_PATH
CCADB_URL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade={decade}"
MATTER_REPO = "project-chip/connectedhomeip"
MATTER_PATH = "credentials/production/paa-root-certs"
MATTER_HEAD_URL = "https://api.github.com/repos/%s/commits/master" % MATTER_REPO
MATTER_DIR_URL = "https://api.github.com/repos/%s/contents/%s?ref={commit}" % (MATTER_REPO, MATTER_PATH)
MATTER_RAW_URL = "https://raw.githubusercontent.com/%s/{commit}/{path}" % MATTER_REPO
CSCA_URL = ("https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/"
            "GermanMasterList.zip?__blob=publicationFile&v=112")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "c509-batch-test"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pem(der):
    return "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n" % base64.encodebytes(der).decode()


def tlv(buf, pos):
    """Tag, content start and content end of the DER element at pos."""
    first = buf[pos + 1]
    if first < 0x80:
        return buf[pos], pos + 2, pos + 2 + first
    n = first & 0x7F
    length = int.from_bytes(buf[pos + 2:pos + 2 + n], "big")
    return buf[pos], pos + 2 + n, pos + 2 + n + length


def children(buf, start, end):
    """(tag, content start, content end, element start) of the elements in buf[start:end]."""
    out, pos = [], start
    while pos < end:
        tag, a, b = tlv(buf, pos)
        out.append((tag, a, b, pos))
        pos = b
    return out


def master_list_certificates(ml):
    """The certificates of an ICAO master list (CMS SignedData, DER). The
    signature is not verified."""
    _, a, b = tlv(ml, 0)                               # ContentInfo
    content = children(ml, a, b)[1]                    # [0] EXPLICIT SignedData
    _, a, b = tlv(ml, content[1])
    encap = children(ml, a, b)[2]                      # encapContentInfo
    econtent = children(ml, encap[1], encap[2])[1]     # [0] EXPLICIT OCTET STRING
    tag, a, b = tlv(ml, econtent[1])
    if tag == 0x24:                                    # constructed: concatenate the parts
        data = b"".join(ml[x:y] for _, x, y, _ in children(ml, a, b))
    else:
        data = ml[a:b]
    _, a, b = tlv(data, 0)                             # CscaMasterList
    cert_set = children(data, a, b)[1]                 # certList SET OF Certificate
    return [data[pos:end] for _, _, end, pos in children(data, cert_set[1], cert_set[2])]


def main():
    ap = argparse.ArgumentParser(description="Fetch the inputs for the C509 batch test")
    ap.add_argument("--out", default="../batch_lists", help="output directory")
    ap.add_argument("--tranco", type=int, default=10000, help="domains from the top of Tranco (0: skip)")
    ap.add_argument("--tranco-id", default="", help="Tranco list ID (default: the current list)")
    ap.add_argument("--crux", type=int, default=5000, help="hosts sampled from the CrUX long tail (0: skip)")
    ap.add_argument("--crux-commit", default="", help="commit of zakird/crux-top-lists (default: the latest)")
    ap.add_argument("--seed", type=int, default=1, help="seed of the CrUX sample")
    ap.add_argument("--ccadb", default="2010,2020", help="CCADB decades, comma-separated (empty: skip)")
    ap.add_argument("--matter", action="store_true", help="also fetch the Matter production PAA roots")
    ap.add_argument("--matter-commit", default="", help="commit of %s (default: the latest)" % MATTER_REPO)
    ap.add_argument("--csca", action="store_true", help="also fetch a CSCA master list")
    ap.add_argument("--csca-url", default=CSCA_URL, help="URL of the master list ZIP")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    notes = ["Inputs for the C509 batch test, fetched %s" % datetime.date.today().isoformat(), ""]
    replay = ["./fetch_batch_lists.py"]

    def write_list(name, hosts):
        text = "\n".join(hosts) + "\n"
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
        return sha256(text.encode())

    if args.tranco > 0:
        list_id = args.tranco_id or fetch(TRANCO_ID_URL).decode().strip()
        url = TRANCO_LIST_URL.format(id=list_id, n=args.tranco)
        data = fetch(url)
        hosts = [row[1].strip() for row in csv.reader(io.StringIO(data.decode())) if len(row) > 1]
        name = "tranco_%s_top%d.txt" % (list_id, args.tranco)
        digest = write_list(name, hosts)
        notes += [name,
                  "  source: Tranco list %s, https://tranco-list.eu/list/%s" % (list_id, list_id),
                  "  url: %s" % url,
                  "  sha256 of the download: %s" % sha256(data),
                  "  hosts: %d, one per line; sha256 of this file: %s" % (len(hosts), digest), ""]
        replay.append("--tranco %d --tranco-id %s" % (args.tranco, list_id))
        print("%s: %d hosts" % (name, len(hosts)))
    else:
        replay.append("--tranco 0")

    if args.crux > 0:
        commit = args.crux_commit
        if not commit:
            commit = json.loads(fetch(CRUX_COMMITS_URL).decode())[0]["sha"]
        url = CRUX_URL.format(commit=commit)
        data = fetch(url)
        rows = csv.reader(io.StringIO(gzip.decompress(data).decode()))
        tail = set()
        for row in rows:
            if len(row) < 2 or not row[1].isdigit() or int(row[1]) <= 10000:
                continue
            origin = row[0]
            if origin.startswith("https://"):
                tail.add(origin[len("https://"):].split("/")[0].split(":")[0].lower())
        pool = sorted(tail)
        sample = random.Random(args.seed).sample(pool, min(args.crux, len(pool)))
        name = "crux_%s_sample%d_seed%d.txt" % (commit[:8], len(sample), args.seed)
        digest = write_list(name, sample)
        notes += [name,
                  "  source: zakird/crux-top-lists, commit %s, %s" % (commit, CRUX_PATH),
                  "  url: %s" % url,
                  "  sha256 of the download: %s" % sha256(data),
                  "  sample: %d of the %d distinct hosts of https origins ranked below the top 10,000;"
                  % (len(sample), len(pool)),
                  "          hosts sorted, then Python random.Random(%d).sample()" % args.seed,
                  "  hosts: one per line; sha256 of this file: %s" % digest, ""]
        replay.append("--crux %d --crux-commit %s --seed %d" % (args.crux, commit, args.seed))
        print("%s: %d hosts" % (name, len(sample)))
    else:
        replay.append("--crux 0")

    decades = [d.strip() for d in args.ccadb.split(",") if d.strip()]
    for decade in decades:
        url = CCADB_URL.format(decade=decade)
        data = fetch(url)
        name = "ccadb_%s.csv" % decade
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)
        count = data.count(b"BEGIN CERTIFICATE")
        notes += [name,
                  "  source: CCADB report 'All Certificate PEMs', NotBeforeDecade=%s" % decade,
                  "  url: %s" % url,
                  "  sha256 of the download: %s" % sha256(data),
                  "  certificates: %d" % count,
                  "  The report is live: a later download can differ. The batch test CSV lists",
                  "  the SHA-256 fingerprint of every certificate that was tested.", ""]
        print("%s: %d certificates" % (name, count))
    replay.append('--ccadb "%s"' % ",".join(decades))

    if args.matter:
        commit = args.matter_commit or json.loads(fetch(MATTER_HEAD_URL).decode())["sha"]
        listing = json.loads(fetch(MATTER_DIR_URL.format(commit=commit)).decode())
        files = sorted(e["path"] for e in listing if e["name"].endswith(".der"))
        bundle = "".join(pem(fetch(MATTER_RAW_URL.format(commit=commit, path=p))) for p in files)
        name = "matter_paa_%s.pem" % commit[:8]
        with open(os.path.join(args.out, name), "w") as f:
            f.write(bundle)
        notes += [name,
                  "  source: %s, commit %s, %s/*.der" % (MATTER_REPO, commit, MATTER_PATH),
                  "  certificates: %d, in file-name order; sha256 of this file: %s"
                  % (len(files), sha256(bundle.encode())), ""]
        replay.append("--matter --matter-commit %s" % commit)
        print("%s: %d certificates" % (name, len(files)))

    if args.csca:
        data = fetch(args.csca_url)
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = [n for n in archive.namelist() if n.lower().endswith(".ml")]
        certs = master_list_certificates(archive.read(members[0]))
        bundle = "".join(pem(c) for c in certs)
        name = "csca_master_list.pem"
        with open(os.path.join(args.out, name), "w") as f:
            f.write(bundle)
        notes += [name,
                  "  source: CSCA master list published by the German BSI, %s" % members[0],
                  "  url: %s" % args.csca_url,
                  "  sha256 of the download: %s" % sha256(data),
                  "  certificates: %d, in list order; sha256 of this file: %s" % (len(certs), sha256(bundle.encode())),
                  "  The signature of the master list is not verified. The list is not to be",
                  "  redistributed from here; see the conditions of use on the BSI page.", ""]
        replay.append('--csca --csca-url "%s"' % args.csca_url)
        print("%s: %d certificates" % (name, len(certs)))

    notes += ["To fetch the same host lists again:", "  " + " ".join(replay), ""]
    with open(os.path.join(args.out, "SOURCES.txt"), "w") as f:
        f.write("\n".join(notes))
    print("Wrote %s" % os.path.join(args.out, "SOURCES.txt"))


if __name__ == "__main__":
    main()
