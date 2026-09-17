"""BS — схема подписи вслепую (§2.3 протокола).

protocol2023.pdf, §2.3: "Схема подписи вслепую 𝐵𝑆 определяется следующими
процессами (используется схема, определенная в работе [9])" — the TeZhu scheme of
Tessaro & Zhu, "Short Pairing-Free Blind Signatures with Exponential Security"
(EUROCRYPT 2022), with

    Hash_blind(m) = Hash(m, DST_blind),
    DST_blind = «BlindSign-TeZhu-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB_Streebog-256_XMD_RO».

`BS.Verify(pk, m, σ)` is the non-interactive verification equation of that scheme
over the curve of §2: with the public key (Q, Z), a signature (c, s, y, t) and
the message m,

    A = s·P − c·y·Q
    C = t·P + y·Z
    проверка: c == Hash_blind(A ‖ C ‖ m) mod q.

Point and scalar encodings follow §2: points are x‖y little-endian, field
elements are 32-byte little-endian strings.  The public key layout (a two-byte
header followed by Q and Z) is not fixed by the document; both the raw 128-byte
form and the 130-byte blob used by the implementation are accepted.

The protocol DST ends with _XMD_RO. RFC 9380 appends its length (80 = ASCII
"P") to form DST_prime; `dst=` takes that already-suffixed byte string.
"""

from __future__ import annotations

from . import curve
from .hashfn import DST_BLIND, DST_BLIND_ROP, xmd_ro


def parse_public_key(blob: bytes) -> tuple[curve.Point, curve.Point]:
    """(Q, Z) from the 130-byte blob or the bare 128-byte pair."""
    if len(blob) == 130:
        body = blob[2:]
    elif len(blob) == 128:
        body = blob
    else:
        raise ValueError(f"unexpected blind signature public key length {len(blob)}")
    return curve.from_le_xy(body[:64]), curve.from_le_xy(body[64:])


class RangeError(ValueError):
    pass


def verify(public_key: bytes, message: bytes, signature: bytes, *,
           dst: bytes = DST_BLIND_ROP) -> bool:
    """BS.Verify(pk, m, σ)."""
    if len(signature) > 128:
        raise RangeError(f"blind signature must be 128 bytes, got {len(signature)}")
    # The chain stores the signature as an integer-like value: leading zero bytes
    # can be dropped (observed: 1 of 2520 signatures arrived 127 bytes long).
    # The official implementation left-pads to 128 bytes, so we do the same and
    # count it, because it is a property of the data, not of the scheme.
    if len(signature) < 128:
        padded = signature.rjust(128, b"\x00")
        signature = padded
    q_point, z_point = parse_public_key(public_key)
    c = int.from_bytes(signature[0:32], "little")
    s = int.from_bytes(signature[32:64], "little")
    y = int.from_bytes(signature[64:96], "little")
    t = int.from_bytes(signature[96:128], "little")

    if not (0 <= c < curve.Q and 0 <= s < curve.Q and
            0 < y < curve.Q and 0 <= t < curve.Q):
        return False
    a_point = curve.mul_add(s, curve.G, -c * y, q_point)
    c_point = curve.mul_add(t, curve.G, y, z_point)
    if a_point is None or c_point is None:
        return False

    statement = curve.to_le_xy(a_point) + curve.to_le_xy(c_point) + message
    challenge = int.from_bytes(xmd_ro(statement, dst), "big") % curve.Q
    return c == challenge


def dst_variants() -> dict[str, bytes]:
    """Both spellings, to be able to report which one the data satisfies."""
    return {"protocol (XMD_RO)": DST_BLIND, "implementation (XMD_ROP)": DST_BLIND_ROP}
