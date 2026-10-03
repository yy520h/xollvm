from dataclasses import dataclass
import pathlib
import re
import subprocess
import sys


SYSTEM_SYMBOLS = {
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
    "strlen", "strcmp", "puts", "abort", "close", "read", "write",
}


@dataclass(frozen=True)
class ArchiveAudit:
    defined_public: tuple[str, ...]
    undefined_external: tuple[str, ...]
    unprefixed_private: tuple[str, ...]
    wrong_architecture: bool = False


def _nm(path: pathlib.Path) -> list[tuple[str, str, str]]:
    result = subprocess.run(["nm", "-A", "-g", str(path)], text=True,
                            capture_output=True, check=True)
    entries = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            entries.append((fields[-3], fields[-2], fields[-1]))
        elif len(fields) == 3:
            entries.append((fields[0], fields[1], fields[2]))
    return entries


def _archive_arch(path: pathlib.Path) -> str:
    """Return the architecture of the first object in the archive."""
    result = subprocess.run(
        ["llvm-readobj", "--file-headers", str(path)],
        text=True, capture_output=True, check=True)
    for line in result.stdout.splitlines():
        if "Machine:" in line:
            return line.split("Machine:")[-1].strip()
    return ""


def audit_archive(path: pathlib.Path, prefix: str, target_triple: str) -> ArchiveAudit:
    entries = _nm(path)
    defined = sorted({name for _, kind, name in entries if kind.upper() not in {"U", "W"}})
    undefined = sorted({name for _, kind, name in entries if kind.upper() == "U"})
    unprefixed = sorted(
        name for name in defined
        if name.startswith(("curl_", "zlib_", "deflate", "inflate", "crc32", "adler32", "compress", "uncompress", "gz", "SSL_", "TLS_", "EVP_", "CRYPTO_", "OPENSSL_", "BIO_", "ERR_", "X509", "RSA_", "DSA_", "EC_", "BN_", "HMAC_", "RAND_", "AES_", "DES_", "MD5_", "SHA", "PKCS", "ASN1_"))
        and not name.startswith(prefix)
    )
    # 修复 #14：验证 archive 架构与 target_triple 一致。
    wrong_arch = False
    if target_triple:
        arch = _archive_arch(path)
        if "aarch64" in target_triple.lower() and "AArch64" not in arch:
            wrong_arch = True
        elif "arm" in target_triple.lower() and "ARM" not in arch:
            wrong_arch = True
        elif "x86_64" in target_triple.lower() and "X86-64" not in arch:
            wrong_arch = True
    return ArchiveAudit(tuple(defined), tuple(undefined), tuple(unprefixed),
                        wrong_architecture=wrong_arch)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--target-triple", default="")
    parser.add_argument("archive", type=pathlib.Path)
    args = parser.parse_args()
    report = audit_archive(args.archive, args.prefix, args.target_triple)
    if report.wrong_architecture:
        print("archive architecture does not match target triple",
              file=sys.stderr)
        return 3
    if report.unprefixed_private:
        print("unprefixed private symbols: " + ", ".join(report.unprefixed_private),
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
