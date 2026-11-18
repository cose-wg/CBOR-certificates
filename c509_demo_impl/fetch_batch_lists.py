#!/usr/bin/env python3
"""Fetch the inputs for the batch test (`c509 t` / `c509 tf`).

Writes into the output directory:

  tranco_<ID>_top<N>.txt        the first N domains of the current Tranco list
  crux_sample<N>_seed<S>.txt    N hosts sampled from the CrUX top-million origins
                                outside the top 10,000 (the long tail)
  ccadb_<DECADE>.csv            CA certificates (PEM in CSV) from the CCADB
  SOURCES.txt                   URL, date, identifier and SHA-256 of every download

Sources:
  Tranco   https://tranco-list.eu          research ranking; each list has a
                                           permanent ID that can be cited
  CrUX     https://github.com/zakird/crux-top-lists
                                           Chrome top-million origins, ranked in
                                           buckets (1000, 10000, 100000, 1000000)
  CCADB    https://www.ccadb.org/resources root and intermediate CA certificates
                                           known to the browser root programmes

Only the Python standard library is used.

Usage:
  ./fetch_batch_lists.py [--out DIR] [--tranco N] [--crux N] [--seed S]
                         [--ccadb DECADE[,DECADE...]]
"""

import argparse
import csv
import datetime
import gzip
import hashlib
import io
import os
import random
import urllib.request

TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_LIST_URL = "https://tranco-list.eu/download/{id}/{n}"
CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
CCADB_URL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade={decade}"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "c509-batch-test"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def main():
    ap = argparse.ArgumentParser(description="Fetch the inputs for the C509 batch test")
    ap.add_argument("--out", default="../batch_lists", help="output directory")
    ap.add_argument("--tranco", type=int, default=10000, help="domains from the top of Tranco (0: skip)")
    ap.add_argument("--crux", type=int, default=5000, help="hosts sampled from the CrUX long tail (0: skip)")
    ap.add_argument("--seed", type=int, default=1, help="seed of the CrUX sample")
    ap.add_argument("--ccadb", default="2010,2020", help="CCADB decades, comma-separated (empty: skip)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    today = datetime.date.today().isoformat()
    notes = ["Inputs for the C509 batch test, fetched %s" % today, ""]

    def record(name, url, data, extra=""):
        notes.append("%s\n  url: %s\n  sha256 of the download: %s%s\n"
                     % (name, url, hashlib.sha256(data).hexdigest(), extra))

    if args.tranco > 0:
        list_id = fetch(TRANCO_ID_URL).decode().strip()
        url = TRANCO_LIST_URL.format(id=list_id, n=args.tranco)
        data = fetch(url)
        hosts = [row[1].strip() for row in csv.reader(io.StringIO(data.decode())) if len(row) > 1]
        name = "tranco_%s_top%d.txt" % (list_id, args.tranco)
        with open(os.path.join(args.out, name), "w") as f:
            f.write("\n".join(hosts) + "\n")
        record(name, url, data,
               "\n  Tranco list ID: %s (https://tranco-list.eu/list/%s)\n  hosts: %d"
               % (list_id, list_id, len(hosts)))
        print("%s: %d hosts" % (name, len(hosts)))

    if args.crux > 0:
        data = fetch(CRUX_URL)
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
        name = "crux_sample%d_seed%d.txt" % (len(sample), args.seed)
        with open(os.path.join(args.out, name), "w") as f:
            f.write("\n".join(sample) + "\n")
        record(name, CRUX_URL, data,
               "\n  sample: %d of %d https origins ranked below the top 10,000, random.Random(%d)"
               % (len(sample), len(pool), args.seed))
        print("%s: %d hosts" % (name, len(sample)))

    for decade in [d.strip() for d in args.ccadb.split(",") if d.strip()]:
        url = CCADB_URL.format(decade=decade)
        data = fetch(url)
        name = "ccadb_%s.csv" % decade
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)
        count = data.count(b"BEGIN CERTIFICATE")
        record(name, url, data, "\n  certificates: %d" % count)
        print("%s: %d certificates" % (name, count))

    with open(os.path.join(args.out, "SOURCES.txt"), "w") as f:
        f.write("\n".join(notes))
    print("Wrote %s" % os.path.join(args.out, "SOURCES.txt"))


if __name__ == "__main__":
    main()
