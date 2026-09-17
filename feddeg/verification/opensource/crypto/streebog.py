"""H — функция хэширования ГОСТ Р 34.11-2012 (Стрибог), 256 бит.

protocol2023.pdf, §2: "𝐻 – хэш-функция Стрибог с длиной выхода 256 битов,
определенная в стандарте ГОСТ Р 34.11–2012 [2]".

The reference implementation is libgcrypt (GnuPG) — an established,
non-Russian library that implements GOST R 34.11-2012 as STRIBOG256; the unit
tests check the two test vectors from the Russian standard's appendix A.1.
"""

from __future__ import annotations

import ctypes
import os
from ctypes.util import find_library

GCRY_MD_STRIBOG256 = 309

# ``find_library`` keeps the verifier usable with libgcrypt's usual Linux,
# macOS and Windows library names.  The algorithm is the same; only the
# dynamic-loader spelling differs by platform.
_library_name = find_library("gcrypt") or next((name for name in (
    "libgcrypt.so.20", "libgcrypt.dylib", "libgcrypt-20.dll"
) if os.path.exists(name)), None)
if _library_name is None:
    raise RuntimeError("libgcrypt with STRIBOG256 is required")
_gcrypt = ctypes.CDLL(_library_name)
_gcrypt.gcry_check_version.restype = ctypes.c_char_p
_gcrypt.gcry_md_map_name.restype = ctypes.c_int
_gcrypt.gcry_md_hash_buffer.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                        ctypes.c_char_p, ctypes.c_size_t]
_gcrypt.gcry_check_version(None)
ALG = _gcrypt.gcry_md_map_name(b"STRIBOG256")
if ALG != GCRY_MD_STRIBOG256:
    raise RuntimeError(f"libgcrypt has no STRIBOG256: {ALG}")


def streebog256(data: bytes) -> bytes:
    """GOST R 34.11-2012, 256-bit output."""
    out = ctypes.create_string_buffer(32)
    _gcrypt.gcry_md_hash_buffer(ALG, out, data, len(data))
    return out.raw


def streebog256_int(data: bytes) -> int:
    """The 32-byte digest as an integer (big-endian, as the implementations do)."""
    return int.from_bytes(streebog256(data), "big")
