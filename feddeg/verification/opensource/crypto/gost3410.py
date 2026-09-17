"""S — схема подписи ГОСТ Р 34.10-2012 (§2.2 протокола).

protocol2023.pdf, §2.2: "Схема подписи 𝑆 … (используется схема, определенная
стандартом ГОСТ Р 34.10–2012 [1])" with 𝐻 = Стрибог-256 and the curve of §2.
Verification is implemented straight from ГОСТ Р 34.10-2012 §6:

    e = h(M) mod q                     (h as an integer)
    v = e⁻¹ mod q
    z₁ = s·v mod q,  z₂ = −r·v mod q
    C = z₁·P + z₂·Q
    проверка: x_C mod q == r

Only the byte order of the digest→integer conversion and of (r, s) are
implementation conventions that the standard fixes for the *representations*
(ГОСТ Р 34.10-2012 §5.3 / RFC 7091 §5.1: the signature is r‖s, each 32 bytes
big-endian); the digest is interpreted here as the standard's §5 conversion
(little-endian) with `digest_le` letting the caller pick the big-endian variant.
The unit tests decide which convention the real blockchain data uses.
"""

from __future__ import annotations

from . import curve
from .streebog import streebog256


def verify(public_key: curve.Point, message: bytes, signature: bytes, *,
           digest_le: bool = True, swap_rs: bool = True) -> bool:
    """S.Verify.  Defaults are the conventions the chain actually uses, measured
    on real 2025 transactions (24/24 verify; the three other combinations give
    0/24): the Стрибог digest is read as a little-endian integer (ГОСТ's own
    §5 conversion of byte strings to numbers) and the 64-byte signature on the
    wire is s‖r, each 32 bytes big-endian.  protocol2023.pdf fixes neither."""
    if len(signature) != 64:
        return False
    first, second = signature[:32], signature[32:]
    if swap_rs:
        first, second = second, first
    r = int.from_bytes(first, "big")
    s = int.from_bytes(second, "big")
    if not (0 < r < curve.Q and 0 < s < curve.Q):
        return False

    digest = streebog256(message)
    e = int.from_bytes(digest, "little" if digest_le else "big") % curve.Q
    if e == 0:
        e = 1
    v = pow(e, -1, curve.Q)
    c = curve.mul_add(s * v % curve.Q, curve.G, (-r * v) % curve.Q, public_key)
    if c is None:
        return False
    return c[0] % curve.Q == r
