#!/usr/bin/env python3
"""
extract_vectors.py

Version-aware extractor for IETF C509 test vector XML files.
Parses draft-ietf-cose-c509-test-vectors-{VERSION}.xml and writes each
<artwork> block to an appropriately typed file in the output directory.

Filenames encode both the draft version and the section number:

    v{VER}_section_{N.N.N}_{anchor_underscored}.{ext}

For example:
    v01_section_3.3.2_x509_selfsign_secp256r1.crt
    v01_section_3.3.3_c509_type_3_certificate_3.cbor.hex

Multiple <artwork> blocks in the same section get a disambiguation suffix:
    v01_section_3.3.4_c509_selfsign_secp256r1.cbor.hex   (plain hex)
    v01_section_3.3.4_c509_selfsign_secp256r1_1.cbor.hex  (annotated hex)

Usage:
    python3 extract_vectors.py --version 01 \\
        --xml path/to/draft-ietf-cose-c509-test-vectors-01.xml \\
        --outdir path/to/test_vectors/

Output extensions:
    .crt          PEM certificate
    .csr          PEM certification request
    .key          PEM private key
    .cbor.hex     Plain hex-encoded C509 CBOR value

Requires: lxml  (pip3 install lxml)
"""

import argparse
import os
import re
import sys
from lxml import etree


# ---------------------------------------------------------------------------
# Section number computation
# ---------------------------------------------------------------------------

def compute_section_numbers(root):
    """
    Walk the <middle> element and assign dotted section numbers to every
    <section> element that has an 'anchor' attribute.
    Returns a dict: anchor_string -> "N.N.N".

    Using anchor strings as keys (not id()) avoids lxml's proxy-object
    instability where the same element may get a different id() on each access.
    """
    numbers: dict[str, str] = {}

    def _is_section(node):
        try:
            return isinstance(node.tag, str) and etree.QName(node.tag).localname == "section"
        except Exception:
            return False

    def _walk(nodes, prefix: str):
        count = 0
        for node in nodes:
            if not _is_section(node):
                continue
            count += 1
            num = f"{prefix}{count}"
            anchor = node.get("anchor", "")
            if anchor:
                numbers[anchor] = num
            _walk(list(node), f"{num}.")

    middle = root.find(".//{*}middle")
    if middle is not None:
        _walk(list(middle), "")

    return numbers


# ---------------------------------------------------------------------------
# Content classification
# ---------------------------------------------------------------------------

def clean_hex(text: str) -> str:
    """Strip annotated-hex decorations and return plain lowercase hex."""
    lines = text.strip().split("\n")
    parts = []
    for line in lines:
        if "#" in line:
            line = line[: line.index("#")]
        line = re.sub(r"^\s*\d+:\s*", "", line)
        parts.append(re.sub(r"[^0-9A-Fa-f]", "", line))
    return "".join(parts).lower()


def classify_content(text: str):
    """
    Return (extension, content) for the artwork block, or (None, None) to skip.

    Skipped:
      - OpenSSL verbose certificate dumps (first line "Certificate:")
      - OpenSSL verbose CSR dumps (first line "Certificate Request:")
    """
    stripped = text.strip()

    # PEM blocks
    if "-----BEGIN" in stripped:
        if "PRIVATE KEY" in stripped:
            return "key", stripped
        if "CERTIFICATE REQUEST" in stripped:
            return "csr", stripped
        if "CERTIFICATE" in stripped:
            return "crt", stripped
        return None, None

    # OpenSSL verbose dumps — first line is exactly "Certificate:" or
    # "Certificate Request:" (without the PEM header markers).
    first_line = stripped.split("\n")[0].rstrip()
    if first_line in ("Certificate:", "Certificate Request:"):
        return None, None

    # Hex blocks (plain or annotated)
    hex_data = clean_hex(stripped)
    if len(hex_data) >= 10 and len(hex_data) % 2 == 0:
        return "cbor.hex", hex_data

    return None, None


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------

def anchor_to_stem(anchor: str) -> str:
    """Convert an XML anchor to a safe filename stem (hyphens → underscores)."""
    return re.sub(r"[^0-9A-Za-z_]", "_", anchor.replace("-", "_"))


def make_filename(version: str, section_num: str, anchor: str, count: int, ext: str) -> str:
    """
    Build the output filename.

    Format:  v{VER}_section_{N.N.N}_{anchor_underscored}[_{count}].{ext}
    The disambiguation suffix _{count} is omitted for the first artwork (count 0).
    """
    stem = anchor_to_stem(anchor)
    if count == 0:
        return f"v{version}_section_{section_num}_{stem}.{ext}"
    else:
        return f"v{version}_section_{section_num}_{stem}_{count}.{ext}"


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------

def extract(xml_path: str, version: str, outdir: str):
    os.makedirs(outdir, exist_ok=True)

    tree = etree.parse(xml_path)
    root = tree.getroot()

    section_numbers = compute_section_numbers(root)

    sections = root.findall(".//{*}section")

    saved = 0
    skipped = 0

    # Per-anchor disambiguation counter
    anchor_count: dict[str, int] = {}

    for section in sections:
        anchor = section.get("anchor", "")
        if not anchor:
            continue

        sec_num = section_numbers.get(anchor, "?")

        name_elem = section.find("{*}name")
        section_name = name_elem.text.strip() if name_elem is not None else anchor

        # Direct <artwork> children only
        artworks = [
            child
            for child in section
            if isinstance(child.tag, str)
            and etree.QName(child.tag).localname == "artwork"
        ]

        for artwork in artworks:
            content = "".join(artwork.itertext())

            ext, data = classify_content(content)
            if ext is None:
                skipped += 1
                continue

            count = anchor_count.get(anchor, 0)
            anchor_count[anchor] = count + 1

            filename = make_filename(version, sec_num, anchor, count, ext)
            out_path = os.path.join(outdir, filename)

            with open(out_path, "w") as f:
                f.write(data if ext == "cbor.hex" else data + "\n")

            print(f"  [saved]  {filename}   ({section_name})")
            saved += 1

    print(f"\n  Total saved: {saved}   Skipped (unclassifiable or verbose dumps): {skipped}")

    return section_numbers, sections


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract C509 test vectors from an IETF XML draft, named by section."
    )
    parser.add_argument("--version", default="01", help="Draft version number (e.g. 01)")
    parser.add_argument("--xml", required=True, help="Path to the XML file")
    parser.add_argument("--outdir", required=True, help="Output directory")
    args = parser.parse_args()

    if not os.path.isfile(args.xml):
        print(f"ERROR: XML file not found: {args.xml}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracting version {args.version} vectors from {args.xml}")
    print(f"Output directory: {args.outdir}")
    print()

    extract(args.xml, args.version, args.outdir)


if __name__ == "__main__":
    main()
