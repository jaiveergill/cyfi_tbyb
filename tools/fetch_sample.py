#!/usr/bin/env python3
"""
Fetch a theZoo sample. Downloads and extracts only; never executes.

    tools/fetch_sample.py <name> <outdir>
    tools/fetch_sample.py <name> <outdir> --source [--only FILE ...]

Without --source the archive is taken from malware/Binaries/ and every
contained file is written to <outdir>/extracted/. With --source it is taken
from malware/Source/Original/, and --only restricts extraction to the named
files, written flat into <outdir>.
"""
import argparse
import hashlib
import io
import pathlib
import zipfile

import requests

RAW = "https://raw.githubusercontent.com/ytisf/theZoo/master/malware"
API = "https://api.github.com/repos/ytisf/theZoo/contents/malware"
PW = b"infected"


def archive_url(tree, name):
    """Locate the archive inside a theZoo entry.

    Most entries hold <name>/<name>.zip, but the directory and the archive do
    not always agree on spelling -- Win32.GravityRat contains
    Win32.GravityRAT.zip -- and some append a suffix, as in
    Raccoon.Stealer.v2.sha.zip. The directory is therefore listed and the .zip
    taken from it, falling back to the conventional name if the listing fails.
    """
    try:
        r = requests.get(f"{API}/{tree}/{name}", timeout=60)
        if r.ok:
            zips = [f["name"] for f in r.json() if f["name"].lower().endswith(".zip")]
            if zips:
                return f"{RAW}/{tree}/{name}/{zips[0]}"
    except requests.RequestException:
        pass
    return f"{RAW}/{tree}/{name}/{name}.zip"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("outdir", type=pathlib.Path)
    ap.add_argument("--source", action="store_true",
                    help="fetch from Source/Original instead of Binaries")
    ap.add_argument("--only", action="append", default=[], metavar="FILE",
                    help="extract only this file (repeatable). A bare name matches "
                         "any path ending in it; include slashes to disambiguate "
                         "when an archive holds several files of the same name.")
    args = ap.parse_args()

    tree = "Source/Original" if args.source else "Binaries"
    url = archive_url(tree, args.name)
    r = requests.get(url, timeout=600)
    r.raise_for_status()

    args.outdir.mkdir(parents=True, exist_ok=True)
    print(f"{url}\n  archive sha256 {hashlib.sha256(r.content).hexdigest()}"
          f"  {len(r.content):,} B")

    if not args.source:
        (args.outdir / url.rsplit("/", 1)[-1]).write_bytes(r.content)

    dest_dir = args.outdir if args.source else args.outdir / "extracted"
    dest_dir.mkdir(exist_ok=True)

    z = zipfile.ZipFile(io.BytesIO(r.content))
    for info in z.infolist():
        if info.is_dir():
            continue
        base = pathlib.Path(info.filename).name
        if args.only and not any(
                info.filename == o or info.filename.endswith("/" + o.lstrip("/"))
                for o in args.only):
            continue
        data = z.read(info.filename, pwd=PW)
        (dest_dir / base).write_bytes(data)
        print(f"  {len(data):>10,} B  sha256 {hashlib.sha256(data).hexdigest()}  {base}")


if __name__ == "__main__":
    main()
