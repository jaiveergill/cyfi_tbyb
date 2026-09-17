#!/usr/bin/env python3
"""
Sample selection: find which of theZoo's compiled binaries are .NET assemblies.

theZoo's conf/maldb.db LANGUAGE column is hand-maintained and incomplete, so a
name/label search misses samples. This downloads candidate binary archives and
checks each contained PE for a CLI header (the thing that actually makes a PE a
.NET assembly), which is the static equivalent of the VirusTotal check the
assignment asks for.

Downloads only. Nothing here executes a sample.
"""
import io
import sys
import zipfile

import requests

RAW = "https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Binaries"
PW = b"infected"


def is_dotnet(data):
    """True if this PE has a CLI header (COM descriptor directory entry 14)."""
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(d) > 14 and d[14].VirtualAddress and d[14].Size:
            return True
    except Exception:
        pass
    return False


def check(name):
    url = f"{RAW}/{name}/{name}.zip"
    try:
        r = requests.get(url, timeout=120)
        if r.status_code != 200:
            return name, "no .zip", []
    except Exception as e:
        return name, f"fetch error: {e.__class__.__name__}", []
    hits = []
    try:
        z = zipfile.ZipFile(io.BytesIO(r.content))
        for info in z.infolist():
            if info.is_dir() or info.file_size > 40 * 1024 * 1024:
                continue
            try:
                data = z.read(info.filename, pwd=PW)
            except Exception:
                continue
            if data[:2] == b"MZ" and is_dotnet(data):
                hits.append((info.filename, len(data)))
    except Exception as e:
        return name, f"zip error: {e.__class__.__name__}", []
    return name, "ok", hits


def main():
    names = sys.argv[1:]
    for n in names:
        name, status, hits = check(n)
        if hits:
            print(f"[.NET] {name}")
            for f, sz in hits:
                print(f"         {sz:>10,} B  {f}")
        else:
            print(f"[    ] {name}  ({status})")


if __name__ == "__main__":
    main()
