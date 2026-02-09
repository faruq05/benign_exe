# import os
# import shutil
# import hashlib
# import subprocess
# import argparse
# import json
# from pathlib import Path

# BUFFER_SIZE = 1024 * 1024
# EXT = ".exe"

# # ------------------ UTILS ------------------ #

# def sha256(file_path):
#     h = hashlib.sha256()
#     with open(file_path, "rb") as f:
#         while chunk := f.read(BUFFER_SIZE):
#             h.update(chunk)
#     return h.hexdigest()


# def is_digitally_signed(file_path):
#     """
#     Uses Windows signtool to verify signature
#     """
#     try:
#         result = subprocess.run(
#             ["powershell", "-Command",
#              f"Get-AuthenticodeSignature '{file_path}' | Select -ExpandProperty Status"],
#             capture_output=True,
#             text=True,
#             timeout=10
#         )
#         return result.stdout.strip() == "Valid"
#     except:
#         return False


# def load_hashes(manifest):
#     hashes = set()
#     if manifest.exists():
#         with open(manifest, "r", encoding="utf-8") as f:
#             for line in f:
#                 try:
#                     hashes.add(json.loads(line)["sha256"])
#                 except:
#                     pass
#     return hashes

# # ------------------ MAIN ------------------ #

# def main(src_dirs, out_dir, max_files):
#     out_dir = Path(out_dir)
#     out_dir.mkdir(parents=True, exist_ok=True)

#     manifest = out_dir / "manifest.jsonl"
#     known_hashes = load_hashes(manifest)

#     scanned = copied = eligible = dupes = errors = 0

#     print(f"[*] OUT: {out_dir}")
#     print(f"[*] EXT: .exe")
#     print(f"[*] require_signed=True")
#     print(f"[*] dedupe=True (loaded {len(known_hashes)} hashes)")
#     print(f"[*] max_files={max_files}")
#     print("-" * 60)
#     print("\n[>] Processing files... please wait\n")
#     for src in src_dirs:
#         src = Path(src)
#         print(f"[*] SRC: {src}")

#         for root, _, files in os.walk(src):
#             for name in files:
#                 if not name.lower().endswith(EXT):
#                     continue

#                 scanned += 1
#                 full_path = Path(root) / name

#                 try:
#                     if not is_digitally_signed(full_path):
#                         continue

#                     eligible += 1
#                     h = sha256(full_path)

#                     if h in known_hashes:
#                         dupes += 1
#                         continue

#                     dst = out_dir / name
#                     if dst.exists():
#                         dst = out_dir / f"{h}_{name}"

#                     shutil.copy2(full_path, dst)

#                     record = {
#                         "sha256": h,
#                         "name": name,
#                         "original_path": str(full_path),
#                         "signed": True
#                     }

#                     with open(manifest, "a", encoding="utf-8") as mf:
#                         mf.write(json.dumps(record) + "\n")

#                     known_hashes.add(h)
#                     copied += 1

#                     if copied % 250 == 0:
#                         print(f"[*] copied={copied} scanned={scanned} eligible={eligible} dupes={dupes} errors={errors}")

#                     if copied >= max_files:
#                         print("[✓] max_files reached")
#                         return

#                 except Exception:
#                     errors += 1

#     print("\n[✓] DONE")
#     print(f"copied={copied} scanned={scanned} eligible={eligible} dupes={dupes} errors={errors}")

# # ------------------ ENTRY ------------------ #

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument(
#         "--out",
#         required=True,
#         help="Output directory for benign EXE files"
#     )
#     parser.add_argument(
#         "--max-files",
#         type=int,
#         default=3000
#     )

#     args = parser.parse_args()

#     SRC_DIRS = [
#         r"C:\Windows\System32",
#         r"C:\Windows\SysWOW64",
#         r"C:\Program Files",
#         r"C:\Program Files (x86)"
#     ]

#     main(SRC_DIRS, args.out, args.max_files)

import argparse

import hashlib

import json

import os

import shutil

import subprocess

from pathlib import Path

from typing import Optional, Set, Dict, Any


# Common PE-bearing extensions (Windows)

DEFAULT_EXTS = [".exe"]


PE_MAGIC = b"MZ"



def is_probably_pe(path: Path) -> bool:

    """Fast check: file starts with 'MZ'."""

    try:

        with path.open("rb") as f:

            return f.read(2) == PE_MAGIC

    except Exception:

        return False



def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:

    h = hashlib.sha256()

    with path.open("rb") as f:

        while True:

            chunk = f.read(chunk_size)

            if not chunk:

                break

            h.update(chunk)

    return h.hexdigest()



def get_authenticode_status(path: Path, timeout_s: int = 20) -> Optional[str]:

    """

    Uses PowerShell Authenticode signature check.

    Returns: "Valid", "NotSigned", "UnknownError", etc., or None if unavailable.

    """

    cmd = [

        "powershell",

        "-NoProfile",

        "-ExecutionPolicy",

        "Bypass",

        "-Command",

        f'(Get-AuthenticodeSignature -FilePath "{str(path)}").Status',

    ]

    try:

        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout_s)

        return out.strip() if out else None

    except Exception:

        return None



def safe_copy(src: Path, dst: Path) -> Optional[str]:

    """Copy file (no execution). Return None if ok, else error string."""

    try:

        dst.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(src, dst)

        return None

    except Exception as e:

        return str(e)



def unique_dest_name(dst_dir: Path, src: Path) -> Path:

    """Avoid filename collisions by suffixing."""

    base = src.stem

    ext = src.suffix.lower()

    candidate = dst_dir / f"{base}{ext}"

    if not candidate.exists():

        return candidate


    i = 1

    while True:

        candidate = dst_dir / f"{base}__{i}{ext}"

        if not candidate.exists():

            return candidate

        i += 1



def load_seen_hashes(manifest_path: Path) -> Set[str]:

    """

    Load previously copied sha256 hashes from an existing manifest.jsonl

    so reruns do not duplicate.

    """

    seen: Set[str] = set()

    if not manifest_path.exists():

        return seen


    try:

        with manifest_path.open("r", encoding="utf-8") as f:

            for line in f:

                line = line.strip()

                if not line:

                    continue

                try:

                    rec = json.loads(line)

                    h = rec.get("sha256")

                    if h:

                        seen.add(h)

                except Exception:

                    continue

    except Exception:

        pass

    return seen



def should_skip_path(p: Path, skip_keywords: Set[str]) -> bool:

    """

    Skip paths that contain certain keywords (case-insensitive).

    Helps avoid Temp/Cache/Downloads if you want.

    """

    s = str(p).lower()

    return any(k in s for k in skip_keywords)



def main():

    parser = argparse.ArgumentParser(

        description="Collect benign PE files from a Windows folder by copying only (no execution)."

    )

    parser.add_argument("--src", required=True, help="Source folder (e.g., C:\\Windows\\System32)")

    parser.add_argument("--out", required=True, help="Output folder (e.g., F:\\benign\\system32)")

    parser.add_argument("--max-files", type=int, default=3000, help="Max files to copy (default 3000)")

    parser.add_argument("--exts", default=",".join(DEFAULT_EXTS),

                        help="Comma-separated extensions to include")

    parser.add_argument("--require-pe", action="store_true",

                        help="Require MZ header (recommended)")

    parser.add_argument("--require-signed", action="store_true",

                        help="Require Authenticode signature status == Valid (recommended for System32)")

    parser.add_argument("--check-sig", action="store_true",

                        help="Check signature but don't require it (records status)")

    parser.add_argument("--skip", default="",

                        help="Comma-separated keywords; paths containing any are skipped (e.g., temp,cache,download)")

    parser.add_argument("--manifest", default="manifest.jsonl",

                        help="Manifest filename inside output folder")

    parser.add_argument("--dedupe", action="store_true",

                        help="Deduplicate by sha256 across runs using the manifest")

    args = parser.parse_args()


    src_dir = Path(args.src)

    out_dir = Path(args.out)

    out_dir.mkdir(parents=True, exist_ok=True)


    manifest_path = out_dir / args.manifest

    exts = {e.strip().lower() for e in args.exts.split(",") if e.strip()}

    skip_keywords = {k.strip().lower() for k in args.skip.split(",") if k.strip()}


    if not src_dir.exists():

        raise SystemExit(f"[!] Source not found: {src_dir}")


    # Load hashes we already copied (optional)

    seen_hashes = load_seen_hashes(manifest_path) if args.dedupe else set()


    scanned = 0

    eligible = 0

    copied = 0

    skipped = 0

    dupes = 0

    errors = 0


    print(f"[*] SRC: {src_dir}")

    print(f"[*] OUT: {out_dir}")

    print(f"[*] EXT: {sorted(exts)}")

    print(f"[*] require_pe={args.require_pe}, require_signed={args.require_signed}, check_sig={args.check_sig}")

    print(f"[*] dedupe={args.dedupe} (loaded {len(seen_hashes)} previous hashes)")

    if skip_keywords:

        print(f"[*] skip keywords: {sorted(skip_keywords)}")

    print(f"[*] max_files={args.max_files}")

    print(f"[*] manifest={manifest_path}")


    with manifest_path.open("a", encoding="utf-8") as mf:

        for p in src_dir.rglob("*"):

            if copied >= args.max_files:

                break

            if not p.is_file():

                continue


            scanned += 1


            if skip_keywords and should_skip_path(p, skip_keywords):

                skipped += 1

                continue


            ext = p.suffix.lower()

            if ext not in exts:

                continue


            eligible += 1


            if args.require_pe and not is_probably_pe(p):

                skipped += 1

                continue


            sig_status = None

            if args.require_signed or args.check_sig:

                sig_status = get_authenticode_status(p)

                if args.require_signed and sig_status != "Valid":

                    skipped += 1

                    continue


            # Hash source file for dedupe & traceability

            try:

                h = sha256_file(p)

            except Exception as e:

                errors += 1

                mf.write(json.dumps({

                    "src": str(p),

                    "status": "hash_failed",

                    "error": str(e),

                }) + "\n")

                continue


            if args.dedupe and h in seen_hashes:

                dupes += 1

                continue


            dst = unique_dest_name(out_dir, p)

            err = safe_copy(p, dst)

            if err is not None:

                errors += 1

                mf.write(json.dumps({

                    "src": str(p),

                    "dst": str(dst),

                    "status": "copy_failed",

                    "error": err,

                    "sha256": h,

                    "sig_status": sig_status,

                }) + "\n")

                continue


            copied += 1

            if args.dedupe:

                seen_hashes.add(h)


            mf.write(json.dumps({

                "src": str(p),

                "dst": str(dst),

                "status": "copied",

                "ext": ext,

                "sha256": h,

                "sig_status": sig_status,

            }) + "\n")


            if copied % 250 == 0:

                print(f"[*] copied={copied} scanned={scanned} eligible={eligible} dupes={dupes} errors={errors}")


    print("\n[+] DONE")

    print(f"[+] scanned : {scanned}")

    print(f"[+] eligible: {eligible}")

    print(f"[+] copied  : {copied}")

    print(f"[+] dupes   : {dupes}")

    print(f"[+] skipped : {skipped}")

    print(f"[+] errors  : {errors}")

    print(f"[+] manifest: {manifest_path}")



if __name__ == "__main__":

    main()
    
  