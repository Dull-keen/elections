"""SE — special encryption scheme and its zero-knowledge proofs (§2.4 протокола).

protocol2023.pdf, §2.4: the scheme is ElGamal over ℰ with the proofs of [7]
(Chaum–Pedersen, "Wallet Databases with Observers", CRYPTO'92) and [8] (Cramer,
Damgård, Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of
Witness Hiding Protocols", CRYPTO'94), with
Hash_DP(m) = Hash(m, DST_DP) and
DST_DP = «ZKP-CP-eqdlog-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB_Streebog-256_XMD_RO».

Ciphertexts and proofs use the structure of the protocol:

    c_j = (A_j, B_j) = (r_j·P, r_j·PK + m_j·P)          (one cell per option)
    range proof for a cell: (A, B, A_s[1..k], B_s[1..k], c[1..k], r[1..k])

`verify_range_proof` checks exactly the two relations of the disjunctive
Chaum–Pedersen proof for each allowed plaintext m_i of the cell and the
Fiat–Shamir challenge over the whole statement:

    r_i·P     == A_s[i] + c_i·A
    r_i·PK    == B_s[i] + c_i·(B − m_i·P)
    Σ c_i     ≡  H(PK, A, B, A_s…, B_s…)  (mod q)

`verify_decryption` checks the Chaum–Pedersen proof π of a partial decryption
(§4.5.4): with P' = sk_part·A the prover publishes (P', w, U1, U2) and

    v = XMD(pollId || LE(U1, U2, A, P', P, PK_part), DST_DP_prime)
    w·A     == v·P'      + U1
    w·P     == v·PK_part + U2

(`P` is the generator; `U1 = u·A`, `U2 = u·P`; the challenge of [7] is
non-interactive by Fiat–Shamir).
"""

from __future__ import annotations

from . import curve
from .hashfn import DST_DP, points_hash_mod_q, xmd_ro


class ProofError(ValueError):
    pass


def verify_range_proof(public_key: curve.Point, messages: list[int], cell: dict) -> bool:
    """The disjunctive Chaum–Pedersen proof that the plaintext is in `messages`."""
    a_point = curve.decompress(cell["A"])
    b_point = curve.decompress(cell["B"])
    as_points = [curve.decompress(p) for p in cell["As"]]
    bs_points = [curve.decompress(p) for p in cell["Bs"]]
    challenges = [int.from_bytes(value, "big") for value in cell["c"]]
    responses = [int.from_bytes(value, "big") for value in cell["r"]]
    if not (len(as_points) == len(bs_points) == len(challenges) == len(responses)):
        raise ProofError("malformed range proof")
    if len(challenges) != len(messages):
        raise ProofError("range proof does not cover the declared message set")

    if any(len(value) != 32 for value in cell["c"] + cell["r"]):
        raise ProofError("range proof scalars must be 32 bytes")
    if any(value >= curve.Q for value in challenges + responses):
        return False
    for index, plaintext in enumerate(messages):
        challenge, response = challenges[index], responses[index]
        # Rearrange each equation into a two-scalar multiplication; no batching.
        if curve.mul_add(response, curve.G, -challenge, a_point) != as_points[index]:
            return False
        shifted = curve.sub(b_point, curve.mul_generator(plaintext))
        if curve.mul_add(response, public_key, -challenge, shifted) != bs_points[index]:
            return False

    expected = points_hash_mod_q([public_key, a_point, b_point] + as_points + bs_points)
    return sum(challenges) % curve.Q == expected


def verify_decryption(public_key: curve.Point, ciphertext: tuple[curve.Point, curve.Point],
                      proof: dict, *, poll_id: str) -> bool:
    """SE.VerifyDecPart — Chaum–Pedersen proof for one partially decrypted cell.

    `proof` holds P (the partial decryption), w, U1, U2 as hex strings.
    `poll_id` is the voting identifier, authenticated as part of the challenge.
    """
    encoded = {key: bytes.fromhex(proof[key]) if isinstance(proof[key], str)
               else proof[key] for key in ("P", "w", "U1", "U2")}
    if len(encoded["w"]) != 32:
        raise ProofError("decryption response must be 32 bytes")
    partial = curve.decompress(encoded["P"])
    w = int.from_bytes(encoded["w"], "big")
    u1 = curve.decompress(encoded["U1"])
    u2 = curve.decompress(encoded["U2"])
    a_point, _ = ciphertext

    if not 0 <= w < curve.Q:
        return False
    # Production transcript, independently matched to CSP hash-call traces.
    # xmd_ro accepts DST_prime, including RFC 9380's one-byte DST length.
    statement = poll_id.encode() + b"".join(curve.to_le_xy(point) for point in
                                           [u1, u2, a_point, partial, curve.G, public_key])
    challenge = int.from_bytes(xmd_ro(statement, DST_DP + bytes([len(DST_DP)])), "big") % curve.Q
    return (curve.mul_add(w, a_point, -challenge, partial) == u1 and
            curve.mul_add(w, curve.G, -challenge, public_key) == u2)
