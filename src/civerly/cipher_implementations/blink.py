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
4 rows. The cipher is built on ``WordSBoxCipher`` (wordsize 4); MixColumn is
a single full-state linear layer (see ``_mix_columns``) and the shuffle layer
acts on the whole state. The (Toeplitz-hash based) tweakey schedule is
implemented as a CiVerLy DAG by :class:`BLINK_KeySchedule_CVL`, which yields
the whitening keys, round keys and tweak hashes that are injected into the
cipher's round-key components via ``set_round_keys``.
"""

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    XOR_CVL,
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule
from civerly.util import int_to_vec, vec_to_int
from civerly.wordsboxcipher import WordSBoxCipher

# ---------------------------------------------------------------------------
# Shared tables
# ---------------------------------------------------------------------------

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


def _check_rounds(a, b, ra, rb):
    """Default ``a``, ``b`` to the variant's ``ra``, ``rb`` and check them."""
    if a is None:
        a = ra
    if b is None:
        b = rb
    assert a >= 0 and b >= 0, "a and b must be non-negative"
    assert a + b <= ra + rb, (
        f"a({a}) + b({b}) exceeds available round keys/constants "
        f"for this variant (max {ra + rb})"
    )
    return a, b


class BLINK_KeySchedule_CVL(KeySchedule):
    def __init__(self, n=64, t=64, tweak=0, key_bytes=None, a=None, b=None):
        r"""
        The Blink tweakey schedule as a CiVerLy DAG.

        Blink XORs five kinds of key material into the state: the whitening
        keys ``w0`` / ``w1``, the round keys ``rk[0..a+b-1]`` and the tweak
        hashes ``h0`` / ``h1`` (``h0 ^ h1`` in the middle stage). They are
        output in the order in which they occur in the cipher::

            w0, rk[0..a-1], h0, rk[a..a+b-1], h0^h1,
            rk[0..b-1], h1, rk[b..a+b-1], w1

        i.e. ``2 * (a + b) + 5`` values of ``n`` bits each, matching the
        ``_rk_components`` of :class:`BLINK_CVL` with the same ``n``, ``t``,
        ``key_bytes``, ``a`` and ``b``.

        The whitening and round keys are slices of the master key and are
        wired directly to the output. The tweak is fixed per instance, so
        each tweak hash is a GF(2)-linear function of the master key: the
        bit-permuted master key ``k'`` (bit ``q`` of ``k'`` is bit
        ``11 q mod |k|`` of the master key) is shifted to obtain the hash
        keys ``hk0`` / ``hk1``, and ``h = H_T(hk)`` is a Toeplitz hash, i.e.
        bit ``p`` of ``h`` is the parity of ``T & (hk >> (n - p))``. Both
        hashes share one ``LinearLayer_CVL`` (Toeplitz matrix of the tweak),
        whose inputs are wired from the master key through the bit
        permutation and shift; ``h0 ^ h1`` is computed by an ``XOR_CVL``.

        INPUT:

            - ``n`` -- integer (default: ``64``); Block size in bits, ``64``
              or ``128``.

            - ``t`` -- integer (default: ``64``); Tweak size in bits.

            - ``tweak`` -- integer (default: ``0``); The tweak.

            - ``key_bytes`` -- integer (optional); Master key size in bytes,
              which selects the variant for ``n = 128`` (``128`` for
              Blink-128a/b, ``160`` for Blink-128A/B). Defaults to ``56`` for
              ``n = 64`` and ``128`` for ``n = 128``.

            - ``a``, ``b`` -- integers (optional); Number of outer / inner
              keyed rounds of the (reduced) cipher, as in :class:`BLINK_CVL`.
              Default to the standard values of the variant.

        EXAMPLES::

            sage: from civerly.cipher_implementations.blink import (
            ....:   BLINK_KeySchedule_CVL)
            sage: ks = BLINK_KeySchedule_CVL(tweak=0x0123456789abcdef)
            sage: ks.input_length, ks.output_length
            (448, 960)
            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
            sage: rks = ks(key)
            sage: len(rks)
            15
            sage: [hex(rk) for rk in rks]
            ['0x97779021b38e7fa1',
             '0x6dd387874a0b52ce',
             '0x762c2df9de6f0d21',
             '0xc877d3e5b68357ae',
             '0xe07c1dc6f302c57e',
             '0xd1d7dec33a246943',
             '0xd6a102d888a467e4',
             '0xd8eac24674a0201e',
             '0x6dd387874a0b52ce',
             '0x762c2df9de6f0d21',
             '0xe07c1dc6f302c57e',
             '0x109d11a3c22377b0',
             '0xd1d7dec33a246943',
             '0xd6a102d888a467e4',
             '0x3022e0ad78c78a06']
            sage: rks[0] == key % 2**64 and rks[-1] == (key >> 64) % 2**64
            True
            sage: rks[7] == rks[3] ^^ rks[11]  # h0 xor h1
            True
            sage: len(BLINK_KeySchedule_CVL(a=1, b=1)(key))
            9
            sage: len(BLINK_KeySchedule_CVL(n=128, t=256, key_bytes=160)(0))
            21
        """
        assert n in [64, 128], f"Block size must be 64 or 128, not {n}!"
        assert t in [64, 128, 256], f"Tweak size {t} not supported!"
        if key_bytes is None:
            key_bytes = (n // 8) * (ra_rb_from_n_t(n, t) + 2)
        state_bytes, tweak_bytes, ra, rb, _, _, _ = _variant_config(n, t, key_bytes)
        a, b = _check_rounds(a, b, ra, rb)

        K = 8 * key_bytes  # master key bits
        hk_bits = 8 * (state_bytes + tweak_bytes)  # bits of hk0 / hk1
        assert 2 * hk_bits - 2 <= K, (
            f"A {key_bytes}-byte key is too short for n={n}, t={t}"
        )
        n_out = 2 * (a + b) + 5
        super().__init__(K, n * n_out, name=f"Blink-{n}-{t}-KeySchedule")
        self.tweak = tweak % (1 << t)

        def mk(p):
            # IN index of bit p of the master key integer (LSB = bit 0).
            return K - 1 - p

        def kp(q):
            # IN index of bit q of the bit-permuted key k'.
            return mk((11 * q) % K)

        # Toeplitz hash h = H_T(hk) as an n x m matrix, m = hk_bits - 1:
        # h bit p = XOR_{k : T_k = 1} hk bit (n - p + k). Bit 0 of hk is never
        # used. Input index v <-> hk bit m - v, output index u <-> h bit n-1-u,
        # so entry (u, v) is T bit m - 1 - u - v.
        m = hk_bits - 1
        mat = matrix(GF(2), n, m, 0)
        for u in range(n):
            for v in range(max(0, m - u - t), m - u):
                mat[u, v] = (self.tweak >> (m - 1 - u - v)) & 1
        hash_layer = LinearLayer_CVL(mat, name="TweakHash")

        # hk0 = k' << 1, hk1 = k' >> (hk_bits - 2) (truncated, bit 0 cleared).
        h0 = self.add_subcipher(
            hash_layer, [(self.IN, (kp(m - 1 - v), v)) for v in range(m)]
        )
        h1 = self.add_subcipher(
            hash_layer,
            [(self.IN, (kp(hk_bits - 2 + m - v), v)) for v in range(m)],
        )
        h01 = self.add_subcipher(
            XOR_CVL(n, name="h0^h1"),
            [(h0, (i, i)) for i in range(n)] + [(h1, (i, n + i)) for i in range(n)],
        )

        # Output slots: (source node, offset) with offset the position of the
        # n-bit value in the master key integer (for slices of the master key).
        def key_slice(j):
            return (self.IN, j * n)

        rk = [key_slice(j + 2) for j in range(ra + rb)]
        slots = [
            key_slice(0),
            *rk[:a],
            (h0, None),
            *rk[a : a + b],
            (h01, None),
            *rk[:b],
            (h1, None),
            *rk[b : a + b],
            key_slice(1),
        ]
        edges = []
        for s, (node, off) in enumerate(slots):
            if off is None:
                edges += [(node, (i, s * n + i)) for i in range(n)]
            else:
                edges += [(node, (mk(off + n - 1 - i), s * n + i)) for i in range(n)]
        self.add_output(edges)
        self._rk_width = n

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into the list of ``2 * (a + b) + 5`` round-key
        integers of ``n`` bits each (see :class:`BLINK_KeySchedule_CVL`).

        INPUT:

            - ``master_key`` -- integer; The master key.

        OUTPUT: List of integers.
        """
        w = self._rk_width
        bits = Cipher.eval(self, int_to_vec(master_key, self.input_length))
        return [
            vec_to_int(bits[i * w : (i + 1) * w])
            for i in range(self.output_length // w)
        ]


# ---------------------------------------------------------------------------
# Public cipher class
# ---------------------------------------------------------------------------


class BLINK_CVL(CipherImplementation_CVL, WordSBoxCipher):
    def __init__(
        self,
        n=64,
        t=64,
        key_schedule=None,
        key=None,
        name=None,
        key_bytes=None,
        a=None,
        b=None,
    ):
        r"""
        The CiVerLy implementation of the Blink tweakable block cipher family.

        The cipher is parameterised by its block size ``n``, tweak size ``t``
        and master key size ``key_bytes``. All key material (whitening keys,
        round keys and tweak hashes) is added via round-key components, which
        are all-zero unless a key schedule and key are given. The round
        constants are fixed and part of the graph.

        INPUT:

            - ``n`` -- integer (default: ``64``); Block size in bits, must be
              ``64`` or ``128``.

            - ``t`` -- integer (default: ``64``); Tweak size in bits, one of
              ``{64, 128, 256}`` for ``n = 64`` and one of ``{128, 256}`` for
              ``n = 128``.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass a :class:`BLINK_KeySchedule_CVL`
              (with the same ``n``, ``t``, ``key_bytes``, ``a`` and ``b``,
              and the tweak) to use the real Blink tweakey schedule,
              or :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (``2 * (a + b) + 5`` of them, ``n`` bits
              each, in the order of :class:`BLINK_KeySchedule_CVL`). Defaults to
              ``None`` (no key schedule, all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The master
              key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys.

            - ``name`` -- string (optional); Name of the cipher instance.
              Defaults to ``"Blink-{n}"``.

            - ``key_bytes`` -- integer (optional); Master key size in bytes,
              which selects the variant (and its round constants) for
              ``n = 128``: ``128`` for Blink-128a/b and ``160`` for
              Blink-128A/B. Defaults to ``56`` for ``n = 64`` and ``128`` for
              ``n = 128``.

            - ``a`` -- integer (optional); Number of outer forward / inverse
              keyed rounds (replaces the variant's default ``ra``). Defaults
              to the standard value for the chosen variant.

            - ``b`` -- integer (optional); Number of inner forward / inverse
              keyed rounds (replaces the variant's default ``rb``). Defaults
              to the standard value for the chosen variant.

        The number of rounds ``R`` is the number of S-box layers of the
        instance, ``2 * (a + b) + 4``. For a reduced instance, pass the same
        ``a`` and ``b`` to :class:`BLINK_KeySchedule_CVL`.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        The test vectors below are taken from ``documentation/blink test
        vectors.md`` (and agree with ``documentation/blink.py``)::

            sage: from civerly.cipher_implementations.blink \
            ....:   import BLINK_CVL, BLINK_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int

            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
            sage: ks = BLINK_KeySchedule_CVL(tweak=0x0123456789abcdef)
            sage: blink = BLINK_CVL(64, 64, key_schedule=ks, key=key)
            sage: hex(vec_to_int(blink(int_to_vec(0, 64))))
            '0xa4a0d10502be846e'

            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
            sage: ks = BLINK_KeySchedule_CVL(t=128,
            ....:   tweak=0x0123456789abcdef0123456789abcdef)
            sage: blink = BLINK_CVL(64, 128, key_schedule=ks, key=key)
            sage: hex(vec_to_int(blink(int_to_vec(0, 64))))
            '0x743e142f17caaae1'

            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
            sage: ks = BLINK_KeySchedule_CVL(n=128, t=128,
            ....:   tweak=0x0123456789abcdef0123456789abcdef)
            sage: blink = BLINK_CVL(128, 128, key_schedule=ks, key=key)
            sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
            '0xb722eef350bb182074a6ff13c967a593'

            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
            sage: ks = BLINK_KeySchedule_CVL(n=128, t=256,
            ....:   tweak=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
            sage: blink = BLINK_CVL(128, 256, key_schedule=ks, key=key)
            sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
            '0x20705a38e00412165bdabcac1dcbdec2'

        The Blink-128A/B variants have a 160-byte key, which has to be
        specified by ``key_bytes`` (both for the cipher, as it determines
        the round numbers and constants, and for the key schedule)::

            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e428962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d
            sage: ks = BLINK_KeySchedule_CVL(n=128, t=128, key_bytes=160,
            ....:   tweak=0x0123456789abcdef0123456789abcdef)
            sage: blink = BLINK_CVL(128, 128, key_bytes=160, key_schedule=ks, key=key)
            sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
            '0x82449f141c183601195b5046eac2b026'

            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e428962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d
            sage: ks = BLINK_KeySchedule_CVL(n=128, t=256, key_bytes=160,
            ....:   tweak=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
            sage: blink = BLINK_CVL(128, 256, key_bytes=160, key_schedule=ks, key=key)
            sage: hex(vec_to_int(blink(int_to_vec(0, 128))))
            '0x8dc41b223bc8cd9923b1297dd27583fc'

        Explicit round keys can be passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: key = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
            sage: rks = BLINK_KeySchedule_CVL(tweak=0x0123456789abcdef)(key)
            sage: blink = BLINK_CVL(
            ....:   64, 64, key_schedule=DefaultKeySchedule_CVL(64, 15), key=rks)
            sage: hex(vec_to_int(blink(int_to_vec(0, 64))))
            '0xa4a0d10502be846e'

        Reduced-round instances can be built by passing ``a`` and ``b``
        (which count *keyed* rounds only; the middle tweak stages ``h0`` /
        center / ``h1`` are always present)::

            sage: from civerly.cipher_implementations.blink import BLINK_CVL
            sage: blink = BLINK_CVL(64, 64, a=1, b=1)
            sage: blink.is_valid
            True
            sage: blink.R
            8

        The key schedule then has to be given the same ``a`` and ``b``::

            sage: ks = BLINK_KeySchedule_CVL(tweak=0x0123456789abcdef, a=1, b=1)
            sage: blink = BLINK_CVL(64, 64, key_schedule=ks, key=key, a=1, b=1)
            sage: len(blink._rk_components) == len(ks(key)) == 9
            True

        Model the smallest reduced instance (``a = b = 0``, i.e. only the
        four middle S-box layers) with SAT::

            sage: from civerly.cipher_implementations.blink import BLINK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: blink = BLINK_CVL(64, 64, a=0, b=0, name="blink-64a")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(30, 40),
            ....:     path=Path(tmpdir))
            ....:   blink.analyse(model_options)
            5248 variables and 14593 clauses were written to ...
            32
        """
        assert n in [64, 128], f"Block size must be 64 or 128, not {n}!"
        assert t in [64, 128, 256], f"Tweak size {t} not supported!"
        if name is None:
            name = f"Blink-{n}"
        if key_bytes is None:
            key_bytes = (n // 8) * (ra_rb_from_n_t(n, t) + 2)

        state_bytes, _tweak_bytes, ra, rb, pbox, rc, rc_prime = _variant_config(
            n, t, key_bytes
        )

        a, b = _check_rounds(a, b, ra, rb)
        R = 2 * (a + b) + 4

        state_nibbles = state_bytes * 2
        word = 4  # nibble

        super().__init__(
            word,
            state_nibbles,
            state_nibbles,
            R=R,
            key_schedule=key_schedule,
            key=key,
            name=name,
        )

        # Fixed round constants (LSB-first bytes -> integer).
        rc_int = [_bytes_to_int(rc[r]) for r in range(ra + rb)]
        rc_prime_int = [_bytes_to_int(rc_prime[r]) for r in range(ra + rb)]

        # ---- Build the graph ------------------------------------------------
        # Blink works on nibbles (4-bit words). We use ``WordSBoxCipher`` with
        # ``wordsize = 4`` so that wordwise MILP modeling stays available while
        # avoiding the ``AESlike`` column-major / Blink row-major transpose
        # mismatch. MixColumns is a single full-state LinearLayer.

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

        # ----- Helpers adding stages to ``self`` ---------------------------
        # Every key XOR is built with constant 0 and collected (in cipher
        # order) in ``self._rk_components``; its value is set by
        # ``set_round_keys``.
        self._rk_components = []

        def add(sub, in_node):
            return self.add_subcipher(
                sub, [(in_node, (i, i)) for i in range(state_nibbles)]
            )

        def add_key(in_node):
            node = add(rk_xor(0), in_node)
            self._rk_components.append(self.nodes[node])
            return node

        def add_fwd_round(in_node, r):
            node = add(fwd_round, in_node)
            self._rk_components.append(self.nodes[node].nodes[fwd_rk])
            self.nodes[node].nodes[fwd_rc].const = rc_int[r]
            return node

        def add_bwd_round(in_node, r):
            node = add(bwd_round, in_node)
            self.nodes[node].nodes[bwd_rc].const = rc_prime_int[r]
            self._rk_components.append(self.nodes[node].nodes[bwd_rk])
            return node

        # ----- Assemble the cipher ----------------------------------------
        # whitening w0
        node = add_key(self.IN)
        # a forward keyed rounds
        for r in range(a):
            node = add_fwd_round(node, r)
        # middle: S, M, AK(h0), P
        node = add(subcells, node)
        node = add(mixcolumns, node)
        node = add_key(node)
        node = add(perm, node)
        # b forward keyed rounds
        for r in range(b):
            node = add_fwd_round(node, a + r)
        # middle: S, M, AK(h0^h1), S
        node = add(subcells, node)
        node = add(mixcolumns, node)
        node = add_key(node)
        node = add(subcells, node)
        # b backward keyed rounds
        for r in range(b):
            node = add_bwd_round(node, r)
        # middle: P^-1, AK(h1), M, S
        node = add(inv_perm, node)
        node = add_key(node)
        node = add(mixcolumns, node)
        node = add(subcells, node)
        # a backward keyed rounds
        for r in range(a):
            node = add_bwd_round(node, b + r)
        # whitening w1
        node = add_key(node)
        self.add_output([(node, (i, i)) for i in range(state_nibbles)])

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)


def ra_rb_from_n_t(n, t):
    """Infer ``ra + rb`` from block/tweak sizes for the default key length."""
    if n == 64:
        return 5
    return 6
