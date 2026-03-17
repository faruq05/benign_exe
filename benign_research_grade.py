import hashlib
import json
import shutil
import subprocess
from pathlib import Path

PE_MAGIC = b"MZ"

EXCLUDE_DIRS = [
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Program Files (x86)"),
]

TRUSTED_PATH_KEYWORDS = [
    "PortableApps",
    "Program Files",
    "Program Files (x86)"
]

MIN_SIZE = 10 * 1024      # 10KB
MAX_SIZE = 50 * 1024 * 1024  # 50MB


def is_excluded(path: Path):
    for ex in EXCLUDE_DIRS:
        try:
            path.relative_to(ex)
            return True
        except ValueError:
            continue
    return False


def is_probably_pe(path: Path):
    try:
        with path.open("rb") as f:
            return f.read(2) == PE_MAGIC
    except:
        return False


def is_reasonable_size(path: Path):
    size = path.stat().st_size
    return MIN_SIZE <= size <= MAX_SIZE


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def get_signature_status(path: Path):
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        f'(Get-AuthenticodeSignature -FilePath "{path}").Status',
    ]
    try:
        out = subprocess.check_output(cmd, text=True)
        return out.strip()
    except:
        return None


def is_trusted_source(path: Path):
    p_str = str(path)
    return any(k in p_str for k in TRUSTED_PATH_KEYWORDS)


def is_junk_exe(path: Path):
    name = path.name.lower()

    junk_keywords = [
        "setup", "install", "update", "unins",
        "helper", "launcher", "crash", "report"
    ]

    return any(k in name for k in junk_keywords)


def safe_copy(src: Path, dst: Path):
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return None
    except Exception as e:
        return str(e)


def unique_dest(dst_dir: Path, src: Path):
    base = src.stem
    ext = src.suffix.lower()

    candidate = dst_dir / f"{base}{ext}"
    if not candidate.exists():
        return candidate

    i = 1
    while True:
        candidate = dst_dir / f"{base}_{i}{ext}"
        if not candidate.exists():
            return candidate
        i += 1


def collect_research_benign(root_dir: Path, out_dir: Path, max_files=30000):

    manifest = out_dir / "manifest.jsonl"
    seen_hashes = set()

    if manifest.exists():
        for line in manifest.read_text().splitlines():
            try:
                seen_hashes.add(json.loads(line)["sha256"])
            except:
                pass

    scanned = copied = skipped = dupes = errors = 0

    print(f"\n[+] Research-grade scan started")

    with manifest.open("a", encoding="utf-8") as mf:

        for p in root_dir.rglob("*.exe"):

            if copied >= max_files:
                break

            if not p.is_file():
                continue

            if is_excluded(p):
                continue

            scanned += 1

            if not is_probably_pe(p):
                skipped += 1
                continue

            if not is_reasonable_size(p):
                skipped += 1
                continue

            if is_junk_exe(p):
                skipped += 1
                continue

            sig = get_signature_status(p)

            # trust logic
            if sig != "Valid" and not is_trusted_source(p):
                skipped += 1
                continue

            try:
                h = sha256_file(p)
            except:
                errors += 1
                continue

            if h in seen_hashes:
                dupes += 1
                continue

            dst = unique_dest(out_dir, p)

            err = safe_copy(p, dst)

            if err:
                errors += 1
                continue

            copied += 1
            seen_hashes.add(h)

            mf.write(json.dumps({
                "src": str(p),
                "dst": str(dst),
                "sha256": h,
                "signature": sig
            }) + "\n")

            if copied % 500 == 0:
                print(f"[+] copied={copied} scanned={scanned}")

    print("\n[✓] Done")
    print(f"scanned={scanned}, copied={copied}, skipped={skipped}, dupes={dupes}, errors={errors}")


def main():
    root = Path(r"C:\\")
    output = Path(r"C:\\benign_research")

    output.mkdir(parents=True, exist_ok=True)

    collect_research_benign(root, output)


if __name__ == "__main__":
    main()