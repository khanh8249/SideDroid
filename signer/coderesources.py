import hashlib
import plistlib
from pathlib import Path

RULES = {
    r"^.*": True,
    r"^.*\.lproj/": {"optional": True, "weight": 1000.0},
    r"^.*\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
    r"^Base\.lproj/": {"weight": 1010.0},
    r"^version.plist$": True,
}

RULES2 = {
    r".*\.dSYM($|/)": {"weight": 11.0},
    r"^(.*/)?\.DS_Store$": {"omit": True, "weight": 2000.0},
    r"^.*": True,
    r"^.*\.lproj/": {"optional": True, "weight": 1000.0},
    r"^.*\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
    r"^Base\.lproj/": {"weight": 1010.0},
    r"^Info\.plist$": {"omit": True, "weight": 20.0},
    r"^PkgInfo$": {"omit": True, "weight": 20.0},
    r"^embedded\.provisionprofile$": {"weight": 20.0},
    r"^version\.plist$": {"weight": 20.0},
}


def build_code_resources(bundle: Path, executable: str, nested=None):
    nested = nested or []
    files = {}
    files2 = {}

    for rel, path in _walk_files(bundle):
        rel = rel.replace("\\", "/")
        if rel == executable or rel.startswith("SC_Info/"):
            continue
        if rel == "_CodeSignature/CodeResources":
            continue
        if rel.startswith("Frameworks/") and "/" in rel[len("Frameworks/"):]:
            continue
        if rel.startswith("PlugIns/") and "/" in rel[len("PlugIns/"):]:
            continue
        if not path.is_file():
            continue

        data = path.read_bytes()
        sha1 = hashlib.sha1(data).digest()
        sha256 = hashlib.sha256(data).digest()
        optional = ".lproj/" in rel
        files[rel] = {"hash": sha1, "optional": True} if optional else sha1
        item = {"hash": sha1, "hash2": sha256}
        if optional:
            item["optional"] = True
        files2[rel] = item

    for rel, data in nested:
        rel = rel.replace("\\", "/")
        files[rel] = hashlib.sha1(data).digest()
        files2[rel] = {
            "hash": hashlib.sha1(data).digest(),
            "hash2": hashlib.sha256(data).digest(),
        }

    obj = {
        "files": files,
        "files2": files2,
        "rules": RULES,
        "rules2": RULES2,
    }
    return plistlib.dumps(obj, fmt=plistlib.FMT_XML, sort_keys=False), obj


def _walk_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file():
            yield path.relative_to(root).as_posix(), path
