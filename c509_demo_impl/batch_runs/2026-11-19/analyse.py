#!/usr/bin/env python3
"""Percentiles and trends of the C509/DER ratio in the batch results.

Joins each result table (one row per certificate) with the DER certificates and
breaks the DER size into components (names, key, signature, extensions). Prints
Markdown tables. Only the Python standard library is used.

usage: analyse.py <results-dir> <batch_lists-dir> <tranco-certs-dir> <crux-certs-dir>

  results-dir        has one directory per set (tranco, crux, ccadb_2020,
                     ccadb_2010, csca, matter_paa) with the batch_*.csv of `c509 t`
                     or `c509 tf`
  batch_lists-dir    has the inputs written by fetch_batch_lists.py
  *-certs-dir        the batch_*_certs directory of a host run made with
                     --keep-certs
"""
import base64, collections, csv, glob, hashlib, os, re, statistics, sys

FINAL, LISTS, TRANCO_CERTS, CRUX_CERTS = sys.argv[1:5]
csv.field_size_limit(10 ** 9)

OIDS = {
    "2.5.29.17": "san", "1.3.6.1.4.1.11129.2.4.2": "sct", "1.3.6.1.5.5.7.1.1": "aia",
    "2.5.29.31": "crldp", "2.5.29.32": "policies", "2.5.29.35": "aki", "2.5.29.14": "ski",
    "2.5.29.15": "ku", "2.5.29.37": "eku", "2.5.29.19": "bc", "2.5.29.30": "nameconstr",
}


def tlv(buf, pos):
    first = buf[pos + 1]
    if first < 0x80:
        return buf[pos], pos + 2, pos + 2 + first
    n = first & 0x7F
    return buf[pos], pos + 2 + n, pos + 2 + n + int.from_bytes(buf[pos + 2:pos + 2 + n], "big")


def kids(buf, start, end):
    out, pos = [], start
    while pos < end:
        tag, a, b = tlv(buf, pos)
        out.append((tag, a, b, pos))
        pos = b
    return out


def oid_text(v):
    arcs, acc = [], 0
    for byte in v:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(acc); acc = 0
    first = arcs[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(x) for x in head + arcs[1:])


def org_of(buf, start, end):
    """The O attribute (or CN if there is none) of a Name."""
    found = {}
    for _, a, b, _ in kids(buf, start, end):              # RDNs
        for _, a2, b2, _ in kids(buf, a, b):               # AttributeTypeAndValue
            parts = kids(buf, a2, b2)
            if len(parts) == 2:
                found[oid_text(buf[parts[0][1]:parts[0][2]])] = buf[parts[1][1]:parts[1][2]].decode("utf-8", "replace")
    return found.get("2.5.4.10") or found.get("2.5.4.3") or "?"


def components(der):
    """DER sizes of the parts of a certificate, or None if it does not parse as v3."""
    try:
        _, a, b = tlv(der, 0)
        top = kids(der, a, b)
        tbs = kids(der, top[0][1], top[0][2])
        if tbs[0][0] != 0xA0:
            return None
        size = lambda e: e[2] - e[3]
        c = {"serial": size(tbs[1]), "issuer": size(tbs[3]), "validity": size(tbs[4]), "subject": size(tbs[5]),
             "spki": size(tbs[6]), "sigvalue": size(top[2]), "sigalgs": size(tbs[2]) + size(top[1])}
        c["issuer_org"] = org_of(der, tbs[3][1], tbs[3][2])
        ext_total, san_names = 0, 0
        for e in tbs[7:]:
            if e[0] != 0xA3:
                continue
            _, a, b = tlv(der, e[1])
            ext_total = size(e)
            c["n_ext"] = 0
            for _, a2, b2, pos in kids(der, a, b):
                parts = kids(der, a2, b2)
                name = OIDS.get(oid_text(der[parts[0][1]:parts[0][2]]), "other_ext")
                c[name] = c.get(name, 0) + (b2 - pos)
                c["n_ext"] += 1
                if name == "san":
                    _, x, y = tlv(der, parts[-1][1])       # OCTET STRING content: GeneralNames
                    san_names = len(kids(der, x, y))
        c["extensions"] = ext_total
        c["san_names"] = san_names
        return c
    except Exception:
        return None


def pems(path):
    text = open(path, errors="replace").read()
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S):
        try:
            yield base64.b64decode("".join(m.group(1).split()))
        except Exception:
            pass


def ders_of(name):
    if name == "tranco" or name == "crux":
        for p in glob.glob(os.path.join(TRANCO_CERTS if name == "tranco" else CRUX_CERTS, "*.der")):
            yield open(p, "rb").read()
    else:
        src = {"ccadb_2020": "ccadb_2020.csv", "ccadb_2010": "ccadb_2010.csv",
               "csca": "csca_master_list.pem", "matter_paa": "matter_paa_71a00964.pem"}[name]
        yield from pems(os.path.join(LISTS, src))


def pct(values, p):
    s = sorted(values)
    if not s:
        return float("nan")
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def load(name):
    table = sorted(glob.glob(os.path.join(FINAL, name, "batch_*.csv")))[-1]
    rows = {r["sha256"]: r for r in csv.DictReader(open(table)) if r["lossless"] == "true"}
    out = []
    for der in ders_of(name):
        r = rows.get(hashlib.sha256(der).hexdigest())
        if r is None or "comp" in r:
            continue
        comp = components(der)
        if comp is None:
            continue
        r["comp"] = comp
        r["der"], r["c509"] = int(r["der_bytes"]), int(r["c509_bytes"])
        r["ratio"] = 100.0 * r["c509"] / r["der"]
        r["saved"] = r["der"] - r["c509"]
        r["set"] = name
        out.append(r)
    return out


PCTS = (1, 5, 10, 25, 50, 75, 90, 95, 99)


def percentile_table(title, groups, field, fmt):
    print("\n### %s\n" % title)
    print("| Group | n | min | " + " | ".join("p%d" % p for p in PCTS) + " | max |")
    print("|---|---|---|" + "---|" * len(PCTS) + "---|")
    for label, rows in groups:
        v = [r[field] for r in rows]
        if not v:
            continue
        print("| %s | %d | %s | %s | %s |" % (label, len(v), fmt % min(v),
              " | ".join(fmt % pct(v, p) for p in PCTS), fmt % max(v)))


def profile(title, rows):
    """Describe a group of certificates."""
    n = len(rows)
    med = lambda f: statistics.median(f(r) for r in rows)
    share = lambda f: 100.0 * sum(f(r) for r in rows) / sum(r["der"] for r in rows)
    keys = collections.Counter("%s / %s" % (r["key"], r["signature"]) for r in rows).most_common(4)
    orgs = collections.Counter(r["comp"]["issuer_org"][:32] for r in rows).most_common(4)
    print("\n**%s** (n=%d): ratio %.1f–%.1f%%, median DER %d bytes, median saved %d bytes, median SAN names %d"
          % (title, n, min(r["ratio"] for r in rows), max(r["ratio"] for r in rows),
             med(lambda r: r["der"]), med(lambda r: r["saved"]), med(lambda r: r["comp"]["san_names"])))
    print("- share of DER bytes: key %.0f%%, signature %.0f%%, SCT list %.0f%%, SAN %.0f%%, names %.0f%%, other extensions %.0f%%"
          % (share(lambda r: r["comp"]["spki"]), share(lambda r: r["comp"]["sigvalue"]),
             share(lambda r: r["comp"].get("sct", 0)), share(lambda r: r["comp"].get("san", 0)),
             share(lambda r: r["comp"]["issuer"] + r["comp"]["subject"]),
             share(lambda r: r["comp"]["extensions"] - r["comp"].get("sct", 0) - r["comp"].get("san", 0))))
    print("- key / signature: " + "; ".join("%s %d%%" % (k, round(100.0 * c / n)) for k, c in keys))
    print("- issuer: " + "; ".join("%s %d%%" % (k, round(100.0 * c / n)) for k, c in orgs))


def corr(xs, ys):
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sx = sum((x - mx) ** 2 for x in xs) ** 0.5
    sy = sum((y - my) ** 2 for y in ys) ** 0.5
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy) if sx and sy else float("nan")


sets = {name: load(name) for name in ("tranco", "crux", "ccadb_2020", "ccadb_2010", "csca", "matter_paa")}
ee = lambda rows: [r for r in rows if r["role"] == "EE"]
ca = lambda rows: [r for r in rows if r["role"] == "CA"]
web_ee = ee(sets["tranco"]) + ee(sets["crux"])
all_ca = ca(sets["tranco"]) + ca(sets["crux"]) + sets["ccadb_2020"] + sets["ccadb_2010"]

groups = [("Tranco end-entity", ee(sets["tranco"])), ("CrUX end-entity", ee(sets["crux"])),
          ("Tranco CA", ca(sets["tranco"])), ("CrUX CA", ca(sets["crux"])),
          ("CCADB 2020s", sets["ccadb_2020"]), ("CCADB 2010s", sets["ccadb_2010"]),
          ("CSCA", sets["csca"]), ("Matter PAA", sets["matter_paa"])]
percentile_table("C509 / DER per certificate (%)", groups, "ratio", "%.1f")
percentile_table("Bytes saved per certificate (DER - C509)", groups, "saved", "%d")
percentile_table("DER size (bytes)", groups, "der", "%d")

# Web end-entity certificates with the SCT list left out of both sizes.
for r in web_ee:
    sd, sc = int(r["sct_der_bytes"]), int(r["sct_c509_bytes"])
    r["ratio_nosct"] = 100.0 * (r["c509"] - sc) / (r["der"] - sd)
percentile_table("Web end-entity certificates, SCT list not counted (%)",
                 [("Tranco end-entity", ee(sets["tranco"])), ("CrUX end-entity", ee(sets["crux"]))],
                 "ratio_nosct", "%.1f")

print("\n### Web end-entity certificates (Tranco + CrUX, %d) by ratio band" % len(web_ee))
s = sorted(web_ee, key=lambda r: r["ratio"])
n = len(s)
bands = [("best 5%", s[:n // 20]), ("5-25%", s[n // 20:n // 4]), ("middle 50%", s[n // 4:3 * n // 4]),
         ("75-95%", s[3 * n // 4:19 * n // 20]), ("worst 5%", s[19 * n // 20:])]
for label, rows in bands:
    profile(label, rows)

print("\n### Web end-entity certificates by key and signature")
print("\n| Key / signature | n | median ratio | p10 | p90 | median DER | median saved |")
print("|---|---|---|---|---|---|---|")
by = collections.defaultdict(list)
for r in web_ee:
    by["%s / %s" % (r["key"], r["signature"])].append(r)
for k, rows in sorted(by.items(), key=lambda kv: -len(kv[1]))[:8]:
    v = [r["ratio"] for r in rows]
    print("| %s | %d | %.1f | %.1f | %.1f | %d | %d |" % (k, len(rows), statistics.median(v), pct(v, 10), pct(v, 90),
          statistics.median(r["der"] for r in rows), statistics.median(r["saved"] for r in rows)))

print("\n### Web end-entity certificates by number of SAN names")
print("\n| SAN names | n | median ratio | median DER | median saved |")
print("|---|---|---|---|---|")
for lo, hi in ((0, 1), (2, 2), (3, 5), (6, 20), (21, 100), (101, 10 ** 6)):
    rows = [r for r in web_ee if lo <= r["comp"]["san_names"] <= hi]
    if rows:
        print("| %s | %d | %.1f | %d | %d |" % ("%d-%d" % (lo, hi) if hi < 10 ** 6 else "%d+" % lo, len(rows),
              statistics.median(r["ratio"] for r in rows), statistics.median(r["der"] for r in rows),
              statistics.median(r["saved"] for r in rows)))

print("\n### Web end-entity certificates by issuer (top 10)")
print("\n| Issuer | n | median ratio | median DER | median saved | main key |")
print("|---|---|---|---|---|---|")
by = collections.defaultdict(list)
for r in web_ee:
    by[r["comp"]["issuer_org"][:36]].append(r)
for k, rows in sorted(by.items(), key=lambda kv: -len(kv[1]))[:10]:
    mk = collections.Counter(r["key"] for r in rows).most_common(1)[0]
    print("| %s | %d | %.1f | %d | %d | %s %d%% |" % (k, len(rows), statistics.median(r["ratio"] for r in rows),
          statistics.median(r["der"] for r in rows), statistics.median(r["saved"] for r in rows),
          mk[0], round(100.0 * mk[1] / len(rows))))

print("\n### Correlation with the ratio (web end-entity certificates)\n")
ys = [r["ratio"] for r in web_ee]
for label, f in (("share of key + signature bytes in DER", lambda r: (r["comp"]["spki"] + r["comp"]["sigvalue"]) / r["der"]),
                 ("share of SCT list bytes", lambda r: r["comp"].get("sct", 0) / r["der"]),
                 ("share of SAN bytes", lambda r: r["comp"].get("san", 0) / r["der"]),
                 ("share of key + signature + SCT + SAN", lambda r: (r["comp"]["spki"] + r["comp"]["sigvalue"] + r["comp"].get("sct", 0) + r["comp"].get("san", 0)) / r["der"]),
                 ("DER size", lambda r: r["der"]),
                 ("bytes saved", lambda r: r["saved"])):
    print("- %s: r = %.2f" % (label, corr([f(r) for r in web_ee], ys)))

print("\n### CA certificates (Tranco, CrUX, CCADB; %d) by ratio band" % len(all_ca))
s = sorted(all_ca, key=lambda r: r["ratio"])
n = len(s)
for label, rows in (("best 5%", s[:n // 20]), ("middle 50%", s[n // 4:3 * n // 4]), ("worst 5%", s[19 * n // 20:])):
    profile(label, rows)

print("\n### Extremes")
for label, rows in (("web end-entity", web_ee), ("CA", all_ca), ("CSCA", sets["csca"])):
    s = sorted(rows, key=lambda r: r["ratio"])
    for tag, r in (("lowest", s[0]), ("highest", s[-1])):
        c = r["comp"]
        print("- %s %s: %.1f%% (%d -> %d bytes), %s / %s, issuer %s, SAN names %d, SAN %d, SCT %d, key %d, signature %d, other extensions %d [%s]"
              % (label, tag, r["ratio"], r["der"], r["c509"], r["key"], r["signature"], c["issuer_org"][:30], c["san_names"],
                 c.get("san", 0), c.get("sct", 0), c["spki"], c["sigvalue"],
                 c["extensions"] - c.get("san", 0) - c.get("sct", 0), r["sha256"][:12]))
