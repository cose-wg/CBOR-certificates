#!/usr/bin/env python3
"""Draw a stratified sample of hosts for the batch test (`c509 t`) from the
Open PageRank list of the top 10 million domains.

List: https://keywordseverywhere.com/openpagerank/top-domains
      (top10milliondomains.csv.zip; columns Rank, Domain, Extension,
      Open Page Rank, Referring Domains)

Strata, one output file each:

  rank_1-100k, rank_100k-1m, rank_1m-3m, rank_3m-10m
        N domains from each rank band.
  cctld
        N/2 domains under country-code (two-letter) top-level domains, balanced:
        the top-level domains take turns, in alphabetical order, each giving its
        next domain, until N/2 are drawn. A small top-level domain is used up
        early; the others end up with equal numbers.
  public
        N/2 domains of public-sector and academic suffixes, balanced over the
        suffixes in the same way: the top-level domains gov, edu, mil and int,
        and second-level labels gov, gob, gouv, go, govt, gv, edu, ac and mil
        under a country-code top-level domain.

The draw does not depend on a random number generator: within a stratum (or
within a top-level domain or suffix for the balanced ones) the domains are
taken in the order of SHA-256("<seed>:<domain>"). A domain is in one stratum
only; the rank bands are drawn first, then `public`, then `cctld`. Names given
with --exclude (hosts already tested) are left out.

Only the Python standard library is used.

usage: sample_openpagerank.py <top10milliondomains.csv.zip> --out DIR
                              [--per-stratum N] [--seed S] [--exclude FILE ...]
"""

import argparse
import collections
import csv
import hashlib
import heapq
import io
import os
import zipfile

BANDS = (("rank_1-100k", 1, 100_000), ("rank_100k-1m", 100_001, 1_000_000),
         ("rank_1m-3m", 1_000_001, 3_000_000), ("rank_3m-10m", 3_000_001, 10_000_000))
PUBLIC_TLDS = {"gov", "edu", "mil", "int"}
PUBLIC_SECOND_LEVEL = {"gov", "gob", "gouv", "go", "govt", "gv", "edu", "ac", "mil"}


def public_suffix(labels):
    """The public-sector or academic suffix of a domain, or None."""
    if labels[-1] in PUBLIC_TLDS:
        return labels[-1]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in PUBLIC_SECOND_LEVEL:
        return labels[-2] + "." + labels[-1]
    return None


def balanced(pools, quota):
    """Round-robin over the groups in alphabetical order; each group's domains
    are in the order of their hash."""
    queues = {g: sorted(items) for g, items in pools.items()}
    out, depth = [], 0
    while len(out) < quota:
        took = False
        for g in sorted(queues):
            if depth < len(queues[g]):
                out.append(queues[g][depth][1])
                took = True
                if len(out) == quota:
                    break
        if not took:
            break
        depth += 1
    return out


def main():
    ap = argparse.ArgumentParser(description="Stratified host sample from the Open PageRank top 10 million")
    ap.add_argument("list", help="top10milliondomains.csv.zip")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--per-stratum", type=int, default=20000, help="domains per rank band")
    ap.add_argument("--seed", default="1", help="seed of the draw")
    ap.add_argument("--exclude", nargs="*", default=[], help="host lists whose names are left out")
    args = ap.parse_args()

    excluded = set()
    for path in args.exclude:
        with open(path) as f:
            for line in f:
                name = line.strip().lower()
                if name:
                    excluded.add(name)
                    excluded.add(name[4:] if name.startswith("www.") else "www." + name)

    n = args.per_stratum
    key = lambda domain: hashlib.sha256(("%s:%s" % (args.seed, domain)).encode()).digest()
    # Per group, keep only as many of the smallest keys as can possibly be drawn.
    keep = n + 2000
    band_heaps = {name: [] for name, _, _ in BANDS}
    public_pools = collections.defaultdict(list)
    cctld_pools = collections.defaultdict(list)
    rows = 0

    def push(heap, item, limit):
        # Collect, and now and then cut back to the `limit` smallest keys.
        heap.append(item)
        if len(heap) > 4 * limit:
            heap[:] = heapq.nsmallest(limit, heap)

    with zipfile.ZipFile(args.list) as z:
        with z.open(z.namelist()[0]) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))
            next(reader)
            for row in reader:
                rows += 1
                rank, domain = int(row[0]), row[1].strip().lower()
                if domain in excluded or "." not in domain:
                    continue
                item = (key(domain), domain)
                for name, lo, hi in BANDS:
                    if lo <= rank <= hi:
                        push(band_heaps[name], item, keep)
                labels = domain.split(".")
                suffix = public_suffix(labels)
                if suffix:
                    push(public_pools[suffix], item, keep)
                if len(labels[-1]) == 2:
                    push(cctld_pools[labels[-1]], item, keep)

    os.makedirs(args.out, exist_ok=True)
    taken = set()
    report = ["Open PageRank top 10 million: %d rows; seed %s; %d names excluded" % (rows, args.seed, len(excluded) // 2), ""]

    def write(name, domains, note):
        text = "\n".join(domains) + "\n"
        path = os.path.join(args.out, "opr_%s.txt" % name)
        with open(path, "w") as f:
            f.write(text)
        taken.update(domains)
        line = "opr_%s.txt: %d domains, %s; sha256 %s" % (name, len(domains), note, hashlib.sha256(text.encode()).hexdigest())
        report.append(line)
        print(line)

    for name, lo, hi in BANDS:
        domains = [d for _, d in heapq.nsmallest(n, band_heaps[name])]
        write("%s" % name, domains, "ranks %d-%d" % (lo, hi))

    def rest(pools):
        return {g: [it for it in heapq.nsmallest(keep, items) if it[1] not in taken] for g, items in pools.items()}

    pub = rest(public_pools)
    write("public", balanced(pub, n // 2), "%d public-sector and academic suffixes" % len(pub))
    cc = rest(cctld_pools)
    write("cctld", balanced(cc, n // 2), "%d country-code top-level domains" % len(cc))

    # Per-group counts of the two balanced strata.
    for name in ("public", "cctld"):
        with open(os.path.join(args.out, "opr_%s.txt" % name)) as f:
            groups = collections.Counter()
            for d in f.read().split():
                labels = d.split(".")
                groups[public_suffix(labels) if name == "public" else labels[-1]] += 1
        top = max(groups.values())
        report.append("opr_%s.txt: %d groups in the sample; at most %d domains from one group; %d groups with fewer than %d"
                      % (name, len(groups), top, sum(1 for c in groups.values() if c < top - 1), top - 1))
    with open(os.path.join(args.out, "opr_SAMPLE.txt"), "w") as f:
        f.write("\n".join(report) + "\n")
    print("\n".join(report[-2:]))


if __name__ == "__main__":
    main()
