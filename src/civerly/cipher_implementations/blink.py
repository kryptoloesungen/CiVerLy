"""
Blink tweakable block cipher -- CiVerLy implementation.

This module implements the Blink family of tweakable block ciphers (Wang et
al., "THF: Designing Low-Latency Tweakable Block Ciphers") as CiVerLy cipher
objects. All six published variants are supported:

    Blink-64a   (64-bit block,  64-bit tweak,  56-byte key,  a=2, b=3)
    Blink-64b   (64-bit block, 128-bit tweak,  56-byte key,  a=2, b=3)
    Blink-128a  (128-bit block, 128-bit tweak, 128-byte key, a=3, b=3)
    Blink-128b  (128-bit block, 256-bit tweak, 128-byte key, a=3, b=3)
    Blink-128A  (128-bit block, 128-bit tweak, 160-byte key, a=3, b=5)
    Blink-128B  (128-bit block, 256-bit tweak, 160-byte key, a=3, b=5)

The internal state is organised as a rectangular array of 4-bit nibbles with
4 rows, which makes ``AESlike`` (wordsize 4) the natural base class: the
MixColumn layer acts column-wise and the shuffle layer acts on the whole
state. The rather involved key schedule (Toeplitz-hash based) is treated as a
black box and baked into the graph as ``RoundkeyXOR_CVL`` constants, exactly
as recommended in ``documentation/README.md`` section 6. This keeps the
cipher fully compatible with the modeling pipeline while still matching the
published test vectors.
"""

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.component import (
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.wordsboxcipher import WordSBoxCipher

# ---------------------------------------------------------------------------
# Shared tables
# ---------------------------------------------------------------------------

HW2 = [
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    1,
    1,
    0,
    0,
    1,
    0,
    1,
    1,
    0,
]

# The 4-bit S-box S(x) of Blink (an involution).
SBOX = SBox(
    [
        0x1,
        0x0,
        0x9,
        0x3,
        0x8,
        0x5,
        0xE,
        0x7,
        0x4,
        0x2,
        0xC,
        0xB,
        0xA,
        0xF,
        0x6,
        0xD,
    ]
)

# The Midori involutory diffusion matrix M.
M_MATRIX = [
    [0, 1, 1, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [1, 1, 1, 0],
]

# Variant-specific shuffle boxes (paper notation, see ``blink.md``).
PBOX_64 = [
    0,
    5,
    11,
    10,
    1,
    6,
    4,
    13,
    2,
    12,
    9,
    15,
    3,
    7,
    14,
    8,
]

PBOX_128 = [
    5,
    12,
    4,
    1,
    17,
    9,
    10,
    16,
    28,
    14,
    21,
    22,
    11,
    27,
    8,
    13,
    2,
    25,
    18,
    3,
    30,
    6,
    19,
    20,
    0,
    23,
    24,
    31,
    7,
    15,
    29,
    26,
]

# Variant-specific round constants (rc and rc'). Indexed by [round][byte].
ROUND_CONST_64 = [
    [0x44, 0x73, 0x70, 0x03, 0x2E, 0x8A, 0x19, 0x13],
    [0x89, 0x6C, 0x4E, 0xEC, 0x98, 0xFA, 0x2E, 0x08],
    [0x6C, 0x0C, 0xE9, 0x34, 0xCF, 0x66, 0x54, 0xBE],
    [0x17, 0x09, 0x47, 0xB5, 0xB5, 0xD5, 0x84, 0x3F],
    [0xAC, 0xB5, 0xDF, 0x98, 0xA6, 0x0B, 0x31, 0xD1],
]

ROUND_CONST_PRIME_64 = [
    [0x58, 0xB6, 0x8E, 0x72, 0x8F, 0x74, 0x95, 0x0D],
    [0xB5, 0x59, 0x5A, 0xC2, 0x1D, 0xA4, 0x54, 0x7B],
    [0xF0, 0x85, 0x60, 0x28, 0x23, 0xB0, 0xD1, 0xC5],
    [0x0E, 0x18, 0x3A, 0x60, 0xB0, 0xDC, 0x79, 0x8E],
    [0x27, 0x4B, 0x31, 0xBD, 0xC1, 0x77, 0x15, 0xD7],
]

ROUND_CONST_128a = [
    [
        0x44,
        0x73,
        0x70,
        0x03,
        0x2E,
        0x8A,
        0x19,
        0x13,
        0xD3,
        0x08,
        0xA3,
        0x85,
        0x88,
        0x6A,
        0x3F,
        0x24,
    ],
    [
        0x89,
        0x6C,
        0x4E,
        0xEC,
        0x98,
        0xFA,
        0x2E,
        0x08,
        0xD0,
        0x31,
        0x9F,
        0x29,
        0x22,
        0x38,
        0x09,
        0xA4,
    ],
    [
        0x6C,
        0x0C,
        0xE9,
        0x34,
        0xCF,
        0x66,
        0x54,
        0xBE,
        0x77,
        0x13,
        0xD0,
        0x38,
        0xE6,
        0x21,
        0x28,
        0x45,
    ],
    [
        0x17,
        0x09,
        0x47,
        0xB5,
        0xB5,
        0xD5,
        0x84,
        0x3F,
        0xDD,
        0x50,
        0x7C,
        0xC9,
        0xB7,
        0x29,
        0xAC,
        0xC0,
    ],
    [
        0xAC,
        0xB5,
        0xDF,
        0x98,
        0xA6,
        0x0B,
        0x31,
        0xD1,
        0x1B,
        0xFB,
        0x79,
        0x89,
        0xD9,
        0xD5,
        0x16,
        0x92,
    ],
    [
        0x96,
        0x7E,
        0x26,
        0x6A,
        0xED,
        0xAF,
        0xE1,
        0xB8,
        0xB7,
        0xDF,
        0x1A,
        0xD0,
        0xDB,
        0x72,
        0xFD,
        0x2F,
    ],
]

ROUND_CONST_PRIME_128a = [
    [
        0x58,
        0xB6,
        0x8E,
        0x72,
        0x8F,
        0x74,
        0x95,
        0x0D,
        0x7E,
        0x3D,
        0x93,
        0xF4,
        0xA3,
        0xFE,
        0x58,
        0xA4,
    ],
    [
        0xB5,
        0x59,
        0x5A,
        0xC2,
        0x1D,
        0xA4,
        0x54,
        0x7B,
        0xEE,
        0x4A,
        0x15,
        0x82,
        0x58,
        0xCD,
        0x8B,
        0x71,
    ],
    [
        0xF0,
        0x85,
        0x60,
        0x28,
        0x23,
        0xB0,
        0xD1,
        0xC5,
        0x13,
        0x60,
        0xF2,
        0x2A,
        0x39,
        0xD5,
        0x30,
        0x9C,
    ],
    [
        0x0E,
        0x18,
        0x3A,
        0x60,
        0xB0,
        0xDC,
        0x79,
        0x8E,
        0xEF,
        0x38,
        0xDB,
        0xB8,
        0x18,
        0x79,
        0x41,
        0xCA,
    ],
    [
        0x27,
        0x4B,
        0x31,
        0xBD,
        0xC1,
        0x77,
        0x15,
        0xD7,
        0x3E,
        0x8A,
        0x1E,
        0xB0,
        0x8B,
        0x0E,
        0x9E,
        0x6C,
    ],
    [
        0x94,
        0xAB,
        0x55,
        0xAA,
        0xF3,
        0x25,
        0x55,
        0xE6,
        0x60,
        0x5C,
        0x60,
        0x55,
        0xDA,
        0x2F,
        0xAF,
        0x78,
    ],
]

ROUND_CONST_128A = [
    [
        0x44,
        0x73,
        0x70,
        0x03,
        0x2E,
        0x8A,
        0x19,
        0x13,
        0xD3,
        0x08,
        0xA3,
        0x85,
        0x88,
        0x6A,
        0x3F,
        0x24,
    ],
    [
        0x89,
        0x6C,
        0x4E,
        0xEC,
        0x98,
        0xFA,
        0x2E,
        0x08,
        0xD0,
        0x31,
        0x9F,
        0x29,
        0x22,
        0x38,
        0x09,
        0xA4,
    ],
    [
        0x6C,
        0x0C,
        0xE9,
        0x34,
        0xCF,
        0x66,
        0x54,
        0xBE,
        0x77,
        0x13,
        0xD0,
        0x38,
        0xE6,
        0x21,
        0x28,
        0x45,
    ],
    [
        0x17,
        0x09,
        0x47,
        0xB5,
        0xB5,
        0xD5,
        0x84,
        0x3F,
        0xDD,
        0x50,
        0x7C,
        0xC9,
        0xB7,
        0x29,
        0xAC,
        0xC0,
    ],
    [
        0xAC,
        0xB5,
        0xDF,
        0x98,
        0xA6,
        0x0B,
        0x31,
        0xD1,
        0x1B,
        0xFB,
        0x79,
        0x89,
        0xD9,
        0xD5,
        0x16,
        0x92,
    ],
    [
        0x96,
        0x7E,
        0x26,
        0x6A,
        0xED,
        0xAF,
        0xE1,
        0xB8,
        0xB7,
        0xDF,
        0x1A,
        0xD0,
        0xDB,
        0x72,
        0xFD,
        0x2F,
    ],
    [
        0xF7,
        0x6C,
        0x91,
        0xB3,
        0x47,
        0x99,
        0xA1,
        0x24,
        0x99,
        0x7F,
        0x2C,
        0xF1,
        0x45,
        0x90,
        0x7C,
        0xBA,
    ],
    [
        0x69,
        0x4E,
        0x57,
        0x71,
        0xD8,
        0x20,
        0x69,
        0x63,
        0x16,
        0xFC,
        0x8E,
        0x85,
        0xE2,
        0xF2,
        0x01,
        0x08,
    ],
]

ROUND_CONST_PRIME_128A = [
    [
        0x58,
        0xB6,
        0x8E,
        0x72,
        0x8F,
        0x74,
        0x95,
        0x0D,
        0x7E,
        0x3D,
        0x93,
        0xF4,
        0xA3,
        0xFE,
        0x58,
        0xA4,
    ],
    [
        0xB5,
        0x59,
        0x5A,
        0xC2,
        0x1D,
        0xA4,
        0x54,
        0x7B,
        0xEE,
        0x4A,
        0x15,
        0x82,
        0x58,
        0xCD,
        0x8B,
        0x71,
    ],
    [
        0xF0,
        0x85,
        0x60,
        0x28,
        0x23,
        0xB0,
        0xD1,
        0xC5,
        0x13,
        0x60,
        0xF2,
        0x2A,
        0x39,
        0xD5,
        0x30,
        0x9C,
    ],
    [
        0x0E,
        0x18,
        0x3A,
        0x60,
        0xB0,
        0xDC,
        0x79,
        0x8E,
        0xEF,
        0x38,
        0xDB,
        0xB8,
        0x18,
        0x79,
        0x41,
        0xCA,
    ],
    [
        0x27,
        0x4B,
        0x31,
        0xBD,
        0xC1,
        0x77,
        0x15,
        0xD7,
        0x3E,
        0x8A,
        0x1E,
        0xB0,
        0x8B,
        0x0E,
        0x9E,
        0x6C,
    ],
    [
        0x94,
        0xAB,
        0x55,
        0xAA,
        0xF3,
        0x25,
        0x55,
        0xE6,
        0x60,
        0x5C,
        0x60,
        0x55,
        0xDA,
        0x2F,
        0xAF,
        0x78,
    ],
    [
        0xB6,
        0x10,
        0xAB,
        0x2A,
        0x6A,
        0x39,
        0xCA,
        0x55,
        0x40,
        0x14,
        0xE8,
        0x63,
        0x62,
        0x98,
        0x48,
        0x57,
    ],
    [
        0x93,
        0xE9,
        0x72,
        0x7C,
        0xAF,
        0x86,
        0x54,
        0xA1,
        0xCE,
        0xE8,
        0x41,
        0x11,
        0x34,
        0x5C,
        0xCC,
        0xB4,
    ],
]


# ---------------------------------------------------------------------------
# Variant configuration
# ---------------------------------------------------------------------------


def _variant_config(block_bits, tweak_bits, key_bytes):
    """Return (state_bytes, tweak_bytes, ra, rb, pbox, rc, rc_prime)."""
    state_bytes = block_bits // 8
    tweak_bytes = tweak_bits // 8
    if block_bits == 64:
        pbox = PBOX_64
        rc = ROUND_CONST_64
        rc_prime = ROUND_CONST_PRIME_64
    else:
        pbox = PBOX_128
        if key_bytes == 128:
            rc = ROUND_CONST_128a
            rc_prime = ROUND_CONST_PRIME_128a
        else:
            rc = ROUND_CONST_128A
            rc_prime = ROUND_CONST_PRIME_128A
    total = key_bytes // state_bytes  # a + b + 2
    # (a, b) per variant
    if block_bits == 64:
        ra, rb = 2, 3
    elif key_bytes == 128:
        ra, rb = 3, 3
    else:
        ra, rb = 3, 5
    assert ra + rb + 2 == total, (
        f"Inconsistent key length: got {key_bytes} bytes for "
        f"a={ra}, b={rb}, state_bytes={state_bytes}"
    )
    return state_bytes, tweak_bytes, ra, rb, pbox, rc, rc_prime


# ---------------------------------------------------------------------------
# Key schedule (ported faithfully from the reference implementation)
# ---------------------------------------------------------------------------


def _hash_func(key, t, hk_len, state_bytes, tweak_bytes):
    """Compute h = H(k) for a single hash function.

    ``key`` and ``t`` are byte-lists (LSB-first, matching the reference),
    ``hk_len`` is the length of the key used here (``state_bytes + tweak_bytes``).
    Returns the hash as a list of ``state_bytes`` bytes.
    """
    h = [0] * state_bytes
    for i in range(state_bytes - 1, -1, -1):
        h[state_bytes - 1 - i] = 0
        for c in range(8):
            temp = [0] * tweak_bytes
            for j in range(tweak_bytes):
                left = (key[tweak_bytes + i - j] << c) & 0xFF
                right = (key[tweak_bytes + i - j - 1] >> (8 - c)) & 0xFF
                temp[tweak_bytes - 1 - j] = left ^ right
            p = 0
            for j in range(tweak_bytes):
                p ^= t[j] & temp[j]
                p &= 0xFF
            h[state_bytes - 1 - i] ^= HW2[p] << c
            h[state_bytes - 1 - i] &= 0xFF
    return h


def _generate_round_key(master_key, t, state_bytes, tweak_bytes, key_bytes):
    """Port of ``BlinkCipher.generate_round_key``.

    ``master_key`` and ``t`` are byte-lists (LSB-first). Returns
    ``(rk, w, h)`` where each entry is itself a list of ``state_bytes`` bytes.
    """
    key_prime = [0] * key_bytes
    for i in range(key_bytes):
        for j in range(8):
            bit_index = (11 * (8 * i + j)) % (key_bytes * 8)
            byte_idx = bit_index // 8
            bit_in_byte = bit_index % 8
            bit_val = (master_key[byte_idx] >> bit_in_byte) & 1
            key_prime[i] ^= bit_val << j
            key_prime[i] &= 0xFF

    rk = [[0] * state_bytes for _ in range(ra_rb(state_bytes, key_bytes))]
    w = [[0] * state_bytes for _ in range(2)]
    h = [[0] * state_bytes for _ in range(2)]

    for i in range(state_bytes):
        w[0][i] = master_key[i]
        w[1][i] = master_key[i + state_bytes]
        for j in range(len(rk)):
            rk[j][i] = master_key[i + (j + 2) * state_bytes]

    hk_len = state_bytes + tweak_bytes
    hk = [[0] * hk_len for _ in range(2)]
    for i in range(hk_len - 1, -1, -1):
        if i > 0:
            hk[0][i] = ((key_prime[i] << 1) ^ (key_prime[i - 1] >> 7)) & 0xFF
            val = (key_prime[i + hk_len] << 2) & 0xFF
            val2 = (key_prime[i + hk_len - 1] >> 6) & 0xFF
            hk[1][i] = (val ^ val2) & 0xFF
        else:
            hk[0][i] = (key_prime[i] << 1) & 0xFF
            val = (key_prime[i + hk_len] << 2) & 0xFF
            val2 = (key_prime[i + hk_len - 1] >> 6) & 0xFF
            hk[1][i] = ((val ^ val2) & 0xFE) & 0xFF

    h[0] = _hash_func(hk[0], t, hk_len, state_bytes, tweak_bytes)
    h[1] = _hash_func(hk[1], t, hk_len, state_bytes, tweak_bytes)
    return rk, w, h


def ra_rb(state_bytes, key_bytes):
    return key_bytes // state_bytes - 2


def _bytes_to_int(byte_list):
    """LSB-first byte list -> integer (byte 0 is the least significant)."""
    return sum(byte_list[i] << (8 * i) for i in range(len(byte_list)))


# ---------------------------------------------------------------------------
# Component construction helpers
# ---------------------------------------------------------------------------


def _mix_columns(state_bytes):
    r"""Build the full-state MixColumn LinearLayer.

    Blink stores its state *row-major* (the ``j``-th nibble of the ``r``-th
    row is at flat index ``j + (n/16) * r``), which is the transpose of the
    ``AESlike`` column-major convention. To avoid any confusion we do *not*
    use the ``AESlike`` column assumption and instead build a single
    ``LinearLayer_CVL`` spanning the whole state. Concretely, the matrix is
    the Kronecker product ``N \otimes I_4`` where ``N`` is the nibble-wise
    mixing matrix (``M`` applied column by column in the reference order).

    CiVerLy represents state vectors MSB-first (vector index ``0`` is the
    most significant bit of the integer), so the bit positions are placed
    accordingly: nibble ``x`` bit ``b`` lives at vector index
    ``total_bits - 1 - (4*x + b)``.
    """
    s = 4
    cols = state_bytes // 2  # n/16 (the number of MixColumn columns)
    state_nibbles = state_bytes * 2
    total_bits = state_nibbles * s
    # N[o][i] = M[r][c] when o = col + cols*r and i = col + cols*c (same col)
    N = [[0] * state_nibbles for _ in range(state_nibbles)]
    for col in range(cols):
        for r in range(4):
            o = col + cols * r
            for c in range(4):
                i = col + cols * c
                N[o][i] = M_MATRIX[r][c]
    mat = matrix(GF(2), total_bits, total_bits, 0)
    for o in range(state_nibbles):
        for i in range(state_nibbles):
            if N[o][i]:
                for b in range(s):
                    row = total_bits - 1 - (4 * o + b)
                    col = total_bits - 1 - (4 * i + b)
                    mat[row, col] = 1
    mc = LinearLayer_CVL(
        mat, branch_number_differential=4, branch_number_linear=4, name="MixColumns"
    )
    return mc


def _inverse_perm(perm):
    """Return the inverse permutation of ``perm``."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def _vec_perm(pbox, state_nibbles):
    r"""Translate Blink's paper permutation into CiVerLy's vector convention.

    Blink (and its reference code) index nibbles *LSB-first* and define the
    shuffle as ``output[i] = input[pbox[i]]``. CiVerLy vectors are *MSB-first*,
    so a vector word ``w`` corresponds to integer nibble ``state_nibbles - 1 -
    w``. Mapping the paper permutation through this reversal yields the
    ``perm`` argument expected by ``PermuteLayer_CVL``.
    """
    N = state_nibbles
    perm = [0] * N
    for n in range(N):
        perm[N - 1 - pbox[n]] = N - 1 - n
    return perm


# ---------------------------------------------------------------------------
# Public cipher class
# ---------------------------------------------------------------------------


class BLINK_CVL:
    r"""
    The CiVerLy implementation of the Blink tweakable block cipher family.

    The cipher is parameterised by its block size ``n``, tweak size ``t`` and
    the (master) ``key``. The key schedule is evaluated eagerly (using the
    reference algorithm) and the resulting round keys, whitening keys and hash
    values are baked into the graph as ``RoundkeyXOR_CVL`` constants, which is
    sufficient for differential/linear trail analysis.

    INPUT:

        - ``n`` -- integer; Block size in bits, must be ``64`` or ``128``.

        - ``t`` -- integer; Tweak size in bits, one of ``{64, 128, 256}`` for
          ``n = 64`` and one of ``{128, 256}`` for ``n = 128``.

        - ``key`` -- integer (optional); The master key. Defaults to ``0``,
          which (for non-zero tweak) still yields a valid cipher; for trail
          analysis the concrete value does not matter as it is a constant
          XOR.

        - ``tweak`` -- integer (optional); The tweak. Defaults to ``0``.

        - ``name`` -- string (optional); Name of the cipher instance.

        - ``a`` -- integer (optional); Number of outer forward / inverse
          keyed rounds (replaces the variant's default ``ra``). Defaults to
          the standard value for the chosen block/tweak size.

        - ``b`` -- integer (optional); Number of inner forward / inverse
          keyed rounds (replaces the variant's default ``rb``). Defaults to
          the standard value for the chosen block/tweak size.

        - ``start`` -- integer (optional); 1-based index of the first
          S-box layer to include. When provided, ``a`` and ``b`` only
          determine the variant's keyed-round budget; the slice is built
          over the full sequence of S-box layers (keyed rounds plus the
          four structural middle S-box layers). Useful for isolating
          Superbox trails (e.g. ``start=4`` starts at the input to the
          ``h0`` middle stage).

        - ``end`` -- integer (optional); 1-based index of the last
          S-box layer to include (must be given together with ``start``).

        - ``include_w0`` -- bool (optional); Whether to prepend the initial
          whitening ``w0``. Defaults to ``True`` when ``start`` is
          ``1`` or ``None``, otherwise ``False``.

        - ``include_w1`` -- bool (optional); Whether to append the final
          whitening ``w1``. Defaults to ``True`` when ``end`` equals the
          total number of S-box layers (or when ``start`` is ``None``),
          otherwise ``False``.

    The test vectors below are taken from ``documentation/blink test
    vectors.md`` (and agree with ``documentation/blink.py``)::

        sage: from civerly.cipher_implementations.blink import BLINK_CVL
        sage: from civerly.util import int_to_vec, vec_to_int

        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
        sage: blink = BLINK_CVL(64, 64, key=key, tweak=0x0123456789abcdef)
        sage: hex(vec_to_int(blink(int_to_vec(0, 64))))
        '0xa4a0d10502be846e'

        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
        sage: blink = BLINK_CVL(64, 128, key=key, tweak=0x0123456789abcdef0123456789abcdef)
        sage: hex(vec_to_int(blink(int_to_vec(0, 64))))
        '0x743e142f17caaae1'

        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
        sage: blink = BLINK_CVL(128, 128, key=key, tweak=0x0123456789abcdef0123456789abcdef)
        sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
        '0xb722eef350bb182074a6ff13c967a593'

        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
        sage: blink = BLINK_CVL(128, 256, key=key, tweak=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
        sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
        '0x20705a38e00412165bdabcac1dcbdec2'

        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e428962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d
        sage: blink = BLINK_CVL(128, 128, key=key, tweak=0x0123456789abcdef0123456789abcdef)
        sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
        '0x82449f141c183601195b5046eac2b026'

        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e428962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d
        sage: blink = BLINK_CVL(128, 256, key=key, tweak=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
        sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
        '0x8dc41b223bc8cd9923b1297dd27583fc'

    Reduced-round instances can be built by passing ``a`` and ``b`` (which
    count *keyed* rounds ``R`` only; the middle tweak stages ``h0`` / center /
    ``h1`` are always present in this mode)::

        sage: from civerly.cipher_implementations.blink import BLINK_CVL
        sage: blink = BLINK_CVL(64, 64, a=1, b=1)
        sage: blink.is_valid
        True

    Sliced instances are built with ``start`` / ``end``. Rounds are
    numbered by S-box layer; for the default Blink-64 variant this gives
    ``1 … 14``. Rounds ``1-2`` are the outer forward block, rounds ``4-6``
    the inner forward block, rounds ``9-11`` the inner backward block and
    rounds ``13-14`` the outer backward block. The structural middle
    stages are numbered as rounds too: ``3`` is ``h0`` (S, M, AK(h0), P),
    ``7`` and ``8`` are the two S-boxes of ``hxor`` (with the MixColumn
    and constant XOR between them), and ``12`` is ``h1`` (P^-1, AK(h1),
    M, S). The full sliced cipher reproduces the published test vector::

        sage: from civerly.cipher_implementations.blink import BLINK_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
        sage: blink = BLINK_CVL(64, 64, key=key, tweak=0x0123456789abcdef, start=1, end=14)
        sage: hex(vec_to_int(blink(int_to_vec(0, 64))))
        '0xa4a0d10502be846e'

    Model the cipher with SAT::

        sage: from civerly.cipher_implementations.blink import BLINK_CVL
        sage: from civerly.model_options import *
        sage: import tempfile
        sage: blink = BLINK_CVL(64, 64, start=1, end=3, name="blink-64a")
        sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.SAT,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
        ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:     sat_solver=CRYPTOMINISAT_CVL(),
        ....:     logic_minimizer=ESPRESSO_CVL(),
        ....:     path=Path(tmpdir))
        ....:   blink.analyse(model_options)
        Using existing file ..., make sure it is up to date!
        5712 variables and 14657 clauses were written to ...
        14
    """

    def __init__(
        self,
        n=64,
        t=64,
        key=0,
        tweak=0,
        name=None,
        a=None,
        b=None,
        start=None,
        end=None,
        include_w0=None,
        include_w1=None,
    ):
        if name is None:
            name = f"Blink-{n}"

        assert n in [64, 128], f"Block size must be 64 or 128, not {n}!"
        assert t in [64, 128, 256], f"Tweak size {t} not supported!"

        state_bytes, tweak_bytes, ra, rb, pbox, rc, rc_prime = _variant_config(
            n,
            t,
            (key.bit_length() + 7) // 8
            if key
            else (n // 8) * (ra_rb_from_n_t(n, t) + 2),
        )

        # Determine whether we are in slicing mode or legacy reduced-round mode.
        slicing = start is not None
        # Total number of S-box layers for slicing: keyed rounds plus the
        # four structural middle S-box layers (h0, the two S-boxes in hxor,
        # and the h1 S-box).
        total_sbox_rounds = 2 * (ra + rb) + 4
        if slicing:
            assert end is not None, "end must be provided when start is set"
            assert 1 <= start <= end <= total_sbox_rounds, (
                f"start={start}, end={end} are "
                f"out of range for this variant (1..{total_sbox_rounds})"
            )
            if include_w0 is None:
                include_w0 = start == 1
            if include_w1 is None:
                include_w1 = end == total_sbox_rounds
        else:
            if a is None:
                a = ra
            if b is None:
                b = rb

            assert a >= 0 and b >= 0, "a and b must be non-negative"
            assert a + b <= ra + rb, (
                f"a({a}) + b({b}) exceeds available round keys/constants "
                f"for this variant (max {ra + rb})"
            )
            if include_w0 is None:
                include_w0 = True
            if include_w1 is None:
                include_w1 = True

        # Eagerly evaluate the key schedule. The reference treats the master
        # key and tweak in LSB-first byte order.
        key_bytes = state_bytes * (ra + rb + 2)
        master_key = [(key >> (8 * i)) & 0xFF for i in range(key_bytes)]
        tweak_lst = [(tweak >> (8 * i)) & 0xFF for i in range(tweak_bytes)]
        rk, w, h = _generate_round_key(
            master_key, tweak_lst, state_bytes, tweak_bytes, key_bytes
        )

        # Convert every constant to a single integer (LSB-first bytes).
        rk_int = [_bytes_to_int(rk[r]) for r in range(ra + rb)]
        w0_int = _bytes_to_int(w[0])
        w1_int = _bytes_to_int(w[1])
        h0_int = _bytes_to_int(h[0])
        h1_int = _bytes_to_int(h[1])
        rc_int = [_bytes_to_int(rc[r]) for r in range(ra + rb)]
        rc_prime_int = [_bytes_to_int(rc_prime[r]) for r in range(ra + rb)]
        h_xor_int = h0_int ^ h1_int

        # ---- Build the graph ------------------------------------------------
        # Blink works on nibbles (4-bit words). We use ``WordSBoxCipher`` with
        # ``wordsize = 4`` so that wordwise MILP modeling stays available while
        # avoiding the ``AESlike`` column-major / Blink row-major transpose
        # mismatch. MixColumns is a single full-state LinearLayer.
        state_nibbles = state_bytes * 2
        word = 4  # nibble

        cipher = WordSBoxCipher(word, state_nibbles, state_nibbles, name=name)

        # SubCells: S-box applied to every nibble.
        sbox = SBox_CVL(SBOX, name="SBox")
        subcells = WordSBoxCipher(word, state_nibbles, state_nibbles, name="SubCells")
        for i in range(state_nibbles):
            node = subcells.add_subcipher(sbox, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        # MixColumns: full-state application of M (see ``_mix_columns``).
        mixcolumns = WordSBoxCipher(
            word, state_nibbles, state_nibbles, name="MixColumns"
        )
        mc = _mix_columns(state_bytes)
        node = mixcolumns.add_subcipher(
            mc, [(mixcolumns.IN, (i, i)) for i in range(state_nibbles)]
        )
        mixcolumns.add_output([(node, (i, i)) for i in range(state_nibbles)])

        # Shuffle P and its inverse. The paper defines the shuffle as
        # ``output[i] = input[pbox[i]]`` in LSB-first nibble order; we convert
        # it to CiVerLy's MSB-first vector convention via ``_vec_perm``.
        perm = PermuteLayer_CVL(
            _vec_perm(pbox, state_nibbles), word_coarseness=word, name="Permutation"
        )
        inv_perm = perm.inv()

        # Round-key / constant XOR helper.
        def rk_xor(const):
            return RoundkeyXOR_CVL(state_nibbles * word, const, name="RK")

        # ----- Compose the forward keyed round -----------------------------
        fwd_round = WordSBoxCipher(word, state_nibbles, state_nibbles, name="FwdRound")
        node = fwd_round.add_subcipher(
            subcells, [(fwd_round.IN, (i, i)) for i in range(state_nibbles)]
        )
        node = fwd_round.add_subcipher(
            mixcolumns, [(node, (i, i)) for i in range(state_nibbles)]
        )
        fwd_rk = fwd_round.add_subcipher(
            rk_xor(0), [(node, (i, i)) for i in range(state_nibbles)]
        )
        fwd_rc = fwd_round.add_subcipher(
            rk_xor(0), [(fwd_rk, (i, i)) for i in range(state_nibbles)]
        )
        node = fwd_round.add_subcipher(
            perm, [(fwd_rc, (i, i)) for i in range(state_nibbles)]
        )
        fwd_round.add_output([(node, (i, i)) for i in range(state_nibbles)])

        # ----- Compose the backward (inverse) keyed round ------------------
        bwd_round = WordSBoxCipher(word, state_nibbles, state_nibbles, name="BwdRound")
        node = bwd_round.add_subcipher(
            inv_perm, [(bwd_round.IN, (i, i)) for i in range(state_nibbles)]
        )
        bwd_rc = bwd_round.add_subcipher(
            rk_xor(0), [(node, (i, i)) for i in range(state_nibbles)]
        )
        bwd_rk = bwd_round.add_subcipher(
            rk_xor(0), [(bwd_rc, (i, i)) for i in range(state_nibbles)]
        )
        node = bwd_round.add_subcipher(
            mixcolumns, [(bwd_rk, (i, i)) for i in range(state_nibbles)]
        )
        node = bwd_round.add_subcipher(
            subcells, [(node, (i, i)) for i in range(state_nibbles)]
        )
        bwd_round.add_output([(node, (i, i)) for i in range(state_nibbles)])

        # ----- Helper: a single (S, M, AK(c)) middle stage ----------------
        def middle_stage(cipher_parent, in_node, const, label):
            node = cipher_parent.add_subcipher(
                subcells, [(in_node, (i, i)) for i in range(state_nibbles)]
            )
            node = cipher_parent.add_subcipher(
                mixcolumns, [(node, (i, i)) for i in range(state_nibbles)]
            )
            node = cipher_parent.add_subcipher(
                rk_xor(const), [(node, (i, i)) for i in range(state_nibbles)]
            )
            return node

        # ----- Assemble the cipher ----------------------------------------
        node = cipher.IN
        if include_w0:
            node = cipher.add_subcipher(
                rk_xor(w0_int), [(node, (i, i)) for i in range(state_nibbles)]
            )

        if not slicing:
            # ----- Legacy reduced-round assembly ----------------------------
            # a forward keyed rounds
            for r in range(a):
                node = cipher.add_subcipher(
                    fwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                )
                cipher.nodes[node].nodes[fwd_rk].const = rk_int[r]
                cipher.nodes[node].nodes[fwd_rc].const = rc_int[r]
            # middle: S, M, AK(h0), P
            node = middle_stage(cipher, node, h0_int, "h0")
            node = cipher.add_subcipher(
                perm, [(node, (i, i)) for i in range(state_nibbles)]
            )
            # b forward keyed rounds
            for r in range(b):
                node = cipher.add_subcipher(
                    fwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                )
                cipher.nodes[node].nodes[fwd_rk].const = rk_int[a + r]
                cipher.nodes[node].nodes[fwd_rc].const = rc_int[a + r]
            # middle: S, M, AK(h0^h1), S
            node = middle_stage(cipher, node, h_xor_int, "hxor")
            node = cipher.add_subcipher(
                subcells, [(node, (i, i)) for i in range(state_nibbles)]
            )
            # b backward keyed rounds
            for r in range(b):
                node = cipher.add_subcipher(
                    bwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                )
                cipher.nodes[node].nodes[bwd_rc].const = rc_prime_int[r]
                cipher.nodes[node].nodes[bwd_rk].const = rk_int[r]
            # middle: P^-1, AK(h1), M, S
            node = cipher.add_subcipher(
                inv_perm, [(node, (i, i)) for i in range(state_nibbles)]
            )
            node = cipher.add_subcipher(
                rk_xor(h1_int), [(node, (i, i)) for i in range(state_nibbles)]
            )
            node = cipher.add_subcipher(
                mixcolumns, [(node, (i, i)) for i in range(state_nibbles)]
            )
            node = cipher.add_subcipher(
                subcells, [(node, (i, i)) for i in range(state_nibbles)]
            )
            # a backward keyed rounds
            for r in range(a):
                node = cipher.add_subcipher(
                    bwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                )
                cipher.nodes[node].nodes[bwd_rc].const = rc_prime_int[b + r]
                cipher.nodes[node].nodes[bwd_rk].const = rk_int[b + r]
        else:
            # ----- Round-sliced assembly ------------------------------------
            # We number every S-box layer as a round. The sequence of
            # S-box layers for the full cipher is:
            #
            #   1..a              : forward keyed rounds
            #   a+1               : h0 middle stage (S, M, AK(h0))
            #   a+2 .. a+b+1      : forward inner keyed rounds
            #   a+b+2             : first S-box of hxor stage
            #   a+b+3             : second S-box of hxor stage
            #   a+b+4 .. a+2b+3   : backward inner keyed rounds
            #   a+2b+4            : h1 middle stage S-box (P^-1, AK(h1), M, S)
            #   a+2b+5 .. 2a+2b+4 : backward outer keyed rounds
            #
            # If the slice starts inside a multi-S-box middle stage, it is
            # built from that S-box forward (the preceding operations of the
            # stage are omitted). If the slice ends inside such a stage, the
            # trailing operations are omitted and the slice terminates after
            # that S-box.
            for r in range(start, end + 1):
                if 1 <= r <= ra:
                    # Forward outer round
                    idx = r - 1
                    node = cipher.add_subcipher(
                        fwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    cipher.nodes[node].nodes[fwd_rk].const = rk_int[idx]
                    cipher.nodes[node].nodes[fwd_rc].const = rc_int[idx]
                elif r == ra + 1:
                    # h0 middle stage (always followed by the permutation
                    # that leads to the next round)
                    node = middle_stage(cipher, node, h0_int, "h0")
                    node = cipher.add_subcipher(
                        perm, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                elif ra + 2 <= r <= ra + rb + 1:
                    # Forward inner round
                    idx = r - 2
                    node = cipher.add_subcipher(
                        fwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    cipher.nodes[node].nodes[fwd_rk].const = rk_int[idx]
                    cipher.nodes[node].nodes[fwd_rc].const = rc_int[idx]
                elif r == ra + rb + 2:
                    # First S-box of the hxor stage: SubCells only.
                    node = cipher.add_subcipher(
                        subcells, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    if r < end:
                        node = cipher.add_subcipher(
                            mixcolumns, [(node, (i, i)) for i in range(state_nibbles)]
                        )
                        node = cipher.add_subcipher(
                            rk_xor(h_xor_int),
                            [(node, (i, i)) for i in range(state_nibbles)],
                        )
                elif r == ra + rb + 3:
                    # Second S-box of the hxor stage
                    node = cipher.add_subcipher(
                        subcells, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                elif ra + rb + 4 <= r <= ra + 2 * rb + 3:
                    # Backward inner round
                    idx = r - (ra + rb + 4)
                    node = cipher.add_subcipher(
                        bwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    cipher.nodes[node].nodes[bwd_rc].const = rc_prime_int[idx]
                    cipher.nodes[node].nodes[bwd_rk].const = rk_int[idx]
                elif r == ra + 2 * rb + 4:
                    # h1 middle stage S-box (P^-1, AK(h1), M, S)
                    node = cipher.add_subcipher(
                        inv_perm, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    node = cipher.add_subcipher(
                        rk_xor(h1_int), [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    node = cipher.add_subcipher(
                        mixcolumns, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    node = cipher.add_subcipher(
                        subcells, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                else:
                    # Backward outer round
                    idx = r - (ra + rb + 5)
                    node = cipher.add_subcipher(
                        bwd_round, [(node, (i, i)) for i in range(state_nibbles)]
                    )
                    cipher.nodes[node].nodes[bwd_rc].const = rc_prime_int[idx]
                    cipher.nodes[node].nodes[bwd_rk].const = rk_int[idx]

        if include_w1:
            node = cipher.add_subcipher(
                rk_xor(w1_int), [(node, (i, i)) for i in range(state_nibbles)]
            )
        cipher.add_output([(node, (i, i)) for i in range(state_nibbles)])

        self.blink_cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.blink_cipher


def ra_rb_from_n_t(n, t):
    """Infer ``ra + rb`` from block/tweak sizes for the default key length."""
    if n == 64:
        return 5
    return 6
