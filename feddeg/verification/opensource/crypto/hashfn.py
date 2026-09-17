"""Hash(m, DST) — the hash-to-field function of the protocol.

protocol2023.pdf, §2.1: "Хэш-функция, отображающая двоичные строки конечной длины
в элементы конечного поля ℤ_𝑞, определяется функцией 𝐻𝑎𝑠ℎ. Вход: сообщение 𝑚,
идентификатор области применения 𝐷𝑆𝑇 длины 𝑙 байт. Выход: хэш-значение ℎ ∈ ℤ_𝑞."
The document does not spell out the construction: it is the XMD-RO expansion of
GOST R 34.11-2012 that the DST strings name ("…_Streebog-256_XMD_RO"), with the
domain separation string appended to every block.

Two helpers are needed by the schemes of §2.3–2.4:

* `xmd_ro(message, dst)` — the expand_message_xmd-style construction used by the
  blind signature and partial-decryption proof (dst takes DST_prime);
* `points_hash(points)` — the range-proof challenge and key-aggregation hash,
  NOT the production partial-decryption proof challenge.

Both are implemented from the published constructions; the unit tests check them
against the official implementations on real transactions.
"""

from __future__ import annotations

from . import curve
from .streebog import streebog256

DST_BLIND = (b"BlindSign-TeZhu-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB"
             b"_Streebog-256_XMD_RO")
DST_BLIND_ROP = DST_BLIND + bytes([len(DST_BLIND)])  # RFC 9380 DST_prime (80 = ASCII P)
DST_DP = (b"ZKP-CP-eqdlog-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB"
          b"_Streebog-256_XMD_RO")


def xmd_ro(message: bytes, dst: bytes = DST_BLIND, length: int = 48) -> bytes:
    """XMD expansion; `dst` is the already length-suffixed DST_prime.

    The legacy default is retained for diagnostic comparisons only; callers
    implementing RFC 9380 must append the one-byte original DST length.
    """
    blocks = 2
    if not 0 < length <= 32 * blocks:
        raise ValueError("this instantiation produces up to 64 bytes")
    seed = (b"\x00" * 64 + message
            + (length >> 8).to_bytes(1, "big") + (length & 0xFF).to_bytes(1, "big")
            + b"\x00" + dst)
    first = streebog256(seed)
    previous = b"\x00" * 32
    out = b""
    for index in range(1, blocks + 1):
        previous = streebog256(bytes(a ^ b for a, b in zip(previous, first))
                               + bytes([index]) + dst)
        out += previous
    return out[:length]


def xmd_ro_scalar(message: bytes, dst: bytes = DST_BLIND) -> int:
    return int.from_bytes(xmd_ro(message, dst), "big") % curve.Q


def points_hash(points: list[curve.Point]) -> int:
    """H over a list of points: Streebog-256 of their lowercase hex encoding."""
    source = b"".join(curve.compress(point).hex().encode() for point in points)
    return int.from_bytes(streebog256(source), "big")


def points_hash_mod_q(points: list[curve.Point]) -> int:
    return points_hash(points) % curve.Q
