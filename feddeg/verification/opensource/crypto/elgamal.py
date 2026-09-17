"""SE — гомоморфное сложение, агрегирование ключей и расшифрование (§2.4).

The protocol defines the scheme by its interfaces only:
`SE.KeyAgg(pk₁, pk₂)`, `SE.Add((c₁),…,(cₙ))`, `SE.DecAgg(c̄, μ₁, μ₂, pk₁, pk₂)`.
The concrete arithmetic of the ElGamal variant over ℰ is:

    KeyAgg:  pk = h(pk₁‖pk₂)·pk₁ + h(pk₂‖pk₁)·pk₂,  h = Hash into ℤ_q
    Add:     (ΣA_i, ΣB_i) componentwise, per cell
    DecAgg:  V = B̄ − h(pk₁‖pk₂)·P₁ − h(pk₂‖pk₁)·P₂ with P_j = sk_j·Ā published
             in the partial decryptions, then the discrete logarithm V = v·P
             gives the tally v (v ≤ number of accepted ballots, so it is solved
             by enumeration).

The mixing coefficients are not written down in the document; they are the ones
used by the published implementations (h over the concatenated points, see
`hashfn.points_hash`).
"""

from __future__ import annotations

from . import curve
from .hashfn import points_hash_mod_q

Ciphertext = tuple[curve.Point, curve.Point]


class CiphertextAccumulator:
    """Streaming homomorphic sum without retaining every ballot.

    ``curve.add_many`` is efficient for a known finite list, but a raw dump
    interleaves elections and may contain millions of ballots.  This
    accumulator keeps one Jacobian point per ciphertext cell and converts to
    affine coordinates only once, at the end of an election.
    """

    def __init__(self, shape: list[int]) -> None:
        if not shape or any(count <= 0 for count in shape):
            raise ValueError("invalid ciphertext shape")
        self.shape = list(shape)
        self._points = [
            [(curve._J_INF, curve._J_INF) for _ in range(count)]
            for count in shape
        ]
        self.count = 0

    def add(self, bulletin: list[list[Ciphertext]]) -> None:
        if [len(question) for question in bulletin] != self.shape:
            raise ValueError("inconsistent bulletin dimensions")
        for question_index, question in enumerate(bulletin):
            for cell_index, (a_point, b_point) in enumerate(question):
                a, b = self._points[question_index][cell_index]
                self._points[question_index][cell_index] = (
                    curve._jac_add(a, curve._to_jacobian(a_point)),
                    curve._jac_add(b, curve._to_jacobian(b_point)),
                )
        self.count += 1

    def finish(self) -> list[list[Ciphertext]]:
        if self.count == 0:
            raise ValueError("cannot finish an empty ciphertext sum")
        return [
            [
                (curve._from_jacobian(a), curve._from_jacobian(b))
                for a, b in question
            ]
            for question in self._points
        ]


def key_agg(pk1: curve.Point, pk2: curve.Point) -> curve.Point:
    """SE.KeyAgg — the ballot encryption key of a voting (§4.2.3)."""
    h1 = points_hash_mod_q([pk1, pk2])
    h2 = points_hash_mod_q([pk2, pk1])
    return curve.add(curve.mul(pk1, h1), curve.mul(pk2, h2))


def add(ciphertexts: list[list[list[Ciphertext]]]) -> list[list[Ciphertext]]:
    """SE.Add — homomorphic addition of whole bulletins (per question/cell)."""
    if not ciphertexts:
        raise ValueError("nothing to add")
    shape = [len(question) for question in ciphertexts[0]]
    if any([len(q) for q in ballot] != shape for ballot in ciphertexts):
        raise ValueError("inconsistent bulletin dimensions")
    return [[(curve.add_many(ballot[q][c][0] for ballot in ciphertexts),
              curve.add_many(ballot[q][c][1] for ballot in ciphertexts))
             for c in range(count)] for q, count in enumerate(shape)]


def dec_agg(summed: list[Ciphertext], partials: list[dict], pk1: curve.Point,
            pk2: curve.Point) -> list[int]:
    """SE.DecAgg — the tally per cell from the two partial decryptions."""
    h1 = points_hash_mod_q([pk1, pk2])
    h2 = points_hash_mod_q([pk2, pk1])
    tally = []
    for cell, (master, commission) in zip(summed, partials):
        _, b_point = cell
        p1 = curve.mul(_point(master["P"]), h1)
        p2 = curve.mul(_point(commission["P"]), h2)
        value = curve.sub(b_point, curve.add(p1, p2))
        tally.append(solve_dlp(value, None))
    return tally


def _point(value) -> curve.Point:
    if isinstance(value, str):
        return curve.decompress(bytes.fromhex(value))
    return curve.decompress(value)


def solve_dlp(point: curve.Point, limit: int | None) -> int | None:
    """Smallest v ≥ 0 with point = v·P (enumeration; tallies are small)."""
    if point is None:
        return 0
    target_x = point[0]
    cursor: curve.Point = None
    v = 0
    while limit is None or v <= limit:
        if cursor is not None and cursor[0] == target_x and cursor == point:
            return v
        cursor = curve.add(cursor, curve.G)
        v += 1
        if cursor is None and point is None:
            return v
    return None


def solve_dlp_batch(points: list[curve.Point | None], limit: int) -> dict[int, int | None]:
    """One linear walk resolved against all targets at once (all tallies share it)."""
    if limit < 0:
        raise ValueError("DLP limit must be nonnegative")
    wanted: dict[curve.Point, list[int]] = {}
    found: dict[int, int | None] = {}
    for index, point in enumerate(points):
        found[index] = 0 if point is None else None
        if point is not None:
            wanted.setdefault(point, []).append(index)
    if not wanted:
        return found
    for value, cursor in enumerate(curve.generator_walk(limit)):
        for index in wanted.pop(cursor, []):
            found[index] = value
        if not wanted:
            break
    return found
