r"""
Implementation of the Serpent block cipher.

Serpent is a 32-round SP-network operating on four 32-bit words,
giving a block size of 128 bits. It uses 8 different 4-bit S-boxes
applied in parallel 32 times per round.

The implementation follows the standard Serpent description from the
original specification, including the initial permutation (IP) and
final permutation (FP).

EXAMPLES::

    sage: from civerly.cipher_implementations.serpent import SERPENT_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: serpent = SERPENT_CVL(master_key=0, keylen=128)
    sage: pt = int('8ED77392F29990EDA7A3A3CE6F579DD2', 16)
    sage: ct = vec_to_int(serpent(int_to_vec(pt, 128)))
    sage: hex(ct)
    '0x2d99fd0696ced14886b0e88a968b28b2'

"""

from sage.crypto.sbox import SBox as SBox_sage
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.component import (
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.sboxcipher import SBoxCipher

PHI = 0x9E3779B9

# ---------------------------------------------------------------------------
# IP / FP tables from the Serpent specification
# ---------------------------------------------------------------------------
IP_TABLE = (
    0,
    32,
    64,
    96,
    1,
    33,
    65,
    97,
    2,
    34,
    66,
    98,
    3,
    35,
    67,
    99,
    4,
    36,
    68,
    100,
    5,
    37,
    69,
    101,
    6,
    38,
    70,
    102,
    7,
    39,
    71,
    103,
    8,
    40,
    72,
    104,
    9,
    41,
    73,
    105,
    10,
    42,
    74,
    106,
    11,
    43,
    75,
    107,
    12,
    44,
    76,
    108,
    13,
    45,
    77,
    109,
    14,
    46,
    78,
    110,
    15,
    47,
    79,
    111,
    16,
    48,
    80,
    112,
    17,
    49,
    81,
    113,
    18,
    50,
    82,
    114,
    19,
    51,
    83,
    115,
    20,
    52,
    84,
    116,
    21,
    53,
    85,
    117,
    22,
    54,
    86,
    118,
    23,
    55,
    87,
    119,
    24,
    56,
    88,
    120,
    25,
    57,
    89,
    121,
    26,
    58,
    90,
    122,
    27,
    59,
    91,
    123,
    28,
    60,
    92,
    124,
    29,
    61,
    93,
    125,
    30,
    62,
    94,
    126,
    31,
    63,
    95,
    127,
)

FP_TABLE = (
    0,
    4,
    8,
    12,
    16,
    20,
    24,
    28,
    32,
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    68,
    72,
    76,
    80,
    84,
    88,
    92,
    96,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    1,
    5,
    9,
    13,
    17,
    21,
    25,
    29,
    33,
    37,
    41,
    45,
    49,
    53,
    57,
    61,
    65,
    69,
    73,
    77,
    81,
    85,
    89,
    93,
    97,
    101,
    105,
    109,
    113,
    117,
    121,
    125,
    2,
    6,
    10,
    14,
    18,
    22,
    26,
    30,
    34,
    38,
    42,
    46,
    50,
    54,
    58,
    62,
    66,
    70,
    74,
    78,
    82,
    86,
    90,
    94,
    98,
    102,
    106,
    110,
    114,
    118,
    122,
    126,
    3,
    7,
    11,
    15,
    19,
    23,
    27,
    31,
    35,
    39,
    43,
    47,
    51,
    55,
    59,
    63,
    67,
    71,
    75,
    79,
    83,
    87,
    91,
    95,
    99,
    103,
    107,
    111,
    115,
    119,
    123,
    127,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _rotl32(x, n):
    r"""
    Rotate left a 32-bit word ``x`` by ``n`` bits.

    INPUT:

        - ``x`` -- integer; The 32-bit word to rotate.

        - ``n`` -- integer; Number of bits to rotate by.

    OUTPUT: The rotated 32-bit word.
    """
    x = int(x) & 0xFFFFFFFF
    n = int(n) % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _apply_perm_int(x, perm):
    r"""
    Apply a permutation ``perm`` to the 128-bit integer ``x``.

    Returns a new integer where bit ``p`` is ``x[perm[p]]``.
    """
    result = 0
    for p in range(128):
        if (x >> perm[p]) & 1:
            result |= 1 << p
    return result


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------
def serpent_key_schedule(master_key, keylen=128, R=32):
    r"""
    Generate round keys for the Serpent block cipher.

    Serpent requires 33 128-bit subkeys. The master key is first padded to
    256 bits if necessary, then expanded to 132 prekey words via an affine
    recurrence, and finally transformed by the S-boxes in bitslice mode.
    After the bitslice round key words are produced, the initial
    permutation (IP) is applied to each round key to obtain the
    standard-mode subkeys ``KHat``.

    The round keys are returned as 128-bit integers, compatible with the
    ``rks`` parameter of :class:`SERPENT_CVL`.

    INPUT:

        - ``master_key`` -- integer; The user-supplied master key.

        - ``keylen`` -- integer (default: ``128``); The key length in bits.
          Must be at most ``256``.

        - ``R`` -- integer (default: ``32``); Number of rounds. The function
          returns ``R + 1`` round keys.

    OUTPUT: A list of ``R + 1`` round key integers.

    EXAMPLES::

        sage: from civerly.cipher_implementations.serpent import serpent_key_schedule
        sage: rks = serpent_key_schedule(0, keylen=128)
        sage: len(rks)
        33
        sage: hex(rks[0])
        '0xe5749bf3e92d49bf78ad11abf74966b4'
        sage: hex(rks[1])
        '0x3e602208886902fcc781325fc60cbddc'
        sage: hex(rks[2])
        '0x7d595686772092219d7070d223d44f82'

        sage: rks = serpent_key_schedule(0, keylen=256)
        sage: hex(rks[0])
        '0xe5749bf3ef2d49bf78ad41abf7496624'
        sage: hex(rks[1])
        '0x3e602208726902fcc7d3c25fc60cb03c'
        sage: hex(rks[2])
        '0x7d59567c272092219b4870d223d4d4a2'

    TESTS::

        Verify with the test vector from the NESSIE suite (128-bit key)::

            sage: from civerly.cipher_implementations.serpent import serpent_key_schedule
            sage: key = int("80000000000000000000000000000000", 16)
            sage: rks = serpent_key_schedule(key, keylen=128)
            sage: hex(rks[0])
            '0xe5749bf3e90d49bf78adf0abf74966be'
            sage: hex(rks[1])
            '0x3e602208d1a902fcc78b725fc60cbd79'
            sage: hex(rks[2])
            '0x7d59568107e092219db790d223d4ab69'
    """
    if keylen > 256:
        raise ValueError("Key length must be at most 256 bits")
    if R > 32:
        raise ValueError("Serpent only supports up to 32 rounds")

    key = int(master_key) | 1 << keylen if keylen < 256 else int(master_key)

    # Split 256 key bits into 8 little-endian words.
    w_init = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]

    # Prekey expansion: w[i] for i = -8 .. 131
    raw_w = w_init + [0] * 132
    for i in range(132):
        raw_w[i + 8] = _rotl32(
            raw_w[i] ^ raw_w[i + 3] ^ raw_w[i + 5] ^ raw_w[i + 7] ^ PHI ^ i, 11
        )

    w = raw_w[8:140]

    # Apply bitslice S-boxes to prekeys to obtain 132 round-key words.
    # S-box sequence for each group of 4 prekey words:
    # i=0: S3, i=1: S2, i=2: S1, i=3: S0, i=4: S7, ...
    k = [0] * 132
    for i in range(33):
        which_S = (32 + 3 - i) % 32
        sbox = SERPENT_SBOXES[which_S % 8]
        for j in range(32):
            nibble = 0
            for c in range(4):
                bit = (w[4 * i + c] >> j) & 1
                nibble |= bit << c
            output = int(sbox(nibble))
            for c in range(4):
                bit = (output >> c) & 1
                k[4 * i + c] |= bit << j

    # Pack the 4 words into a 128-bit bitslice integer and apply IP to get
    # the standard-mode round key KHat.
    rks = []
    for i in range(R + 1):
        packed_bitslice = (
            (k[4 * i + 3] << 96)
            | (k[4 * i + 2] << 64)
            | (k[4 * i + 1] << 32)
            | k[4 * i]
        )
        KHat = _apply_perm_int(packed_bitslice, IP_TABLE)
        rks.append(KHat)

    return rks


# ---------------------------------------------------------------------------
# S-boxes
# ---------------------------------------------------------------------------
SERPENT_SBOXES = [
    SBox_sage([3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12]),  # S0
    SBox_sage([15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4]),  # S1
    SBox_sage([8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2]),  # S2
    SBox_sage([0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14]),  # S3
    SBox_sage([1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13]),  # S4
    SBox_sage([15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1]),  # S5
    SBox_sage([7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0]),  # S6
    SBox_sage([1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]),  # S7
]


# ---------------------------------------------------------------------------
# Linear layer
# ---------------------------------------------------------------------------
def _build_serpent_linear_layer():
    r"""
    Build the LinearLayer_CVL for Serpent's linear transformation.

    The linear transformation is defined by the LTTable in the reference
    implementation. This function constructs the corresponding binary matrix
    in the orientation required by :class:`LinearLayer_CVL`.

    TESTS::

        sage: from civerly.cipher_implementations.serpent import _build_serpent_linear_layer
        sage: _build_serpent_linear_layer() # returns LinearLayer_CVL
        LT

    """
    LT_TABLE = [
        [16, 52, 56, 70, 83, 94, 105],
        [72, 114, 125],
        [2, 9, 15, 30, 76, 84, 126],
        [36, 90, 103],
        [20, 56, 60, 74, 87, 98, 109],
        [1, 76, 118],
        [2, 6, 13, 19, 34, 80, 88],
        [40, 94, 107],
        [24, 60, 64, 78, 91, 102, 113],
        [5, 80, 122],
        [6, 10, 17, 23, 38, 84, 92],
        [44, 98, 111],
        [28, 64, 68, 82, 95, 106, 117],
        [9, 84, 126],
        [10, 14, 21, 27, 42, 88, 96],
        [48, 102, 115],
        [32, 68, 72, 86, 99, 110, 121],
        [2, 13, 88],
        [14, 18, 25, 31, 46, 92, 100],
        [52, 106, 119],
        [36, 72, 76, 90, 103, 114, 125],
        [6, 17, 92],
        [18, 22, 29, 35, 50, 96, 104],
        [56, 110, 123],
        [1, 40, 76, 80, 94, 107, 118],
        [10, 21, 96],
        [22, 26, 33, 39, 54, 100, 108],
        [60, 114, 127],
        [5, 44, 80, 84, 98, 111, 122],
        [14, 25, 100],
        [26, 30, 37, 43, 58, 104, 112],
        [3, 118],
        [9, 48, 84, 88, 102, 115, 126],
        [18, 29, 104],
        [30, 34, 41, 47, 62, 108, 116],
        [7, 122],
        [2, 13, 52, 88, 92, 106, 119],
        [22, 33, 108],
        [34, 38, 45, 51, 66, 112, 120],
        [11, 126],
        [6, 17, 56, 92, 96, 110, 123],
        [26, 37, 112],
        [38, 42, 49, 55, 70, 116, 124],
        [2, 15, 76],
        [10, 21, 60, 96, 100, 114, 127],
        [30, 41, 116],
        [0, 42, 46, 53, 59, 74, 120],
        [6, 19, 80],
        [3, 14, 25, 100, 104, 118],
        [34, 45, 120],
        [4, 46, 50, 57, 63, 78, 124],
        [10, 23, 84],
        [7, 18, 29, 104, 108, 122],
        [38, 49, 124],
        [0, 8, 50, 54, 61, 67, 82],
        [14, 27, 88],
        [11, 22, 33, 108, 112, 126],
        [0, 42, 53],
        [4, 12, 54, 58, 65, 71, 86],
        [18, 31, 92],
        [2, 15, 26, 37, 76, 112, 116],
        [4, 46, 57],
        [8, 16, 58, 62, 69, 75, 90],
        [22, 35, 96],
        [6, 19, 30, 41, 80, 116, 120],
        [8, 50, 61],
        [12, 20, 62, 66, 73, 79, 94],
        [26, 39, 100],
        [10, 23, 34, 45, 84, 120, 124],
        [12, 54, 65],
        [16, 24, 66, 70, 77, 83, 98],
        [30, 43, 104],
        [0, 14, 27, 38, 49, 88, 124],
        [16, 58, 69],
        [20, 28, 70, 74, 81, 87, 102],
        [34, 47, 108],
        [0, 4, 18, 31, 42, 53, 92],
        [20, 62, 73],
        [24, 32, 74, 78, 85, 91, 106],
        [38, 51, 112],
        [4, 8, 22, 35, 46, 57, 96],
        [24, 66, 77],
        [28, 36, 78, 82, 89, 95, 110],
        [42, 55, 116],
        [8, 12, 26, 39, 50, 61, 100],
        [28, 70, 81],
        [32, 40, 82, 86, 93, 99, 114],
        [46, 59, 120],
        [12, 16, 30, 43, 54, 65, 104],
        [32, 74, 85],
        [36, 90, 103, 118],
        [50, 63, 124],
        [16, 20, 34, 47, 58, 69, 108],
        [36, 78, 89],
        [40, 94, 107, 122],
        [0, 54, 67],
        [20, 24, 38, 51, 62, 73, 112],
        [40, 82, 93],
        [44, 98, 111, 126],
        [4, 58, 71],
        [24, 28, 42, 55, 66, 77, 116],
        [44, 86, 97],
        [2, 48, 102, 115],
        [8, 62, 75],
        [28, 32, 46, 59, 70, 81, 120],
        [48, 90, 101],
        [6, 52, 106, 119],
        [12, 66, 79],
        [32, 36, 50, 63, 74, 85, 124],
        [52, 94, 105],
        [10, 56, 110, 123],
        [16, 70, 83],
        [0, 36, 40, 54, 67, 78, 89],
        [56, 98, 109],
        [14, 60, 114, 127],
        [20, 74, 87],
        [4, 40, 44, 58, 71, 82, 93],
        [60, 102, 113],
        [3, 18, 72, 114, 118, 125],
        [24, 78, 91],
        [8, 44, 48, 62, 75, 86, 97],
        [64, 106, 117],
        [1, 7, 22, 76, 118, 122],
        [28, 82, 95],
        [12, 48, 52, 66, 79, 90, 101],
        [68, 110, 121],
        [5, 11, 26, 80, 122, 126],
        [32, 86, 99],
    ]

    arr = [[0] * 128 for _ in range(128)]
    for i in range(128):
        for j in LT_TABLE[i]:
            arr[127 - i][127 - j] = 1

    return LinearLayer_CVL(matrix(GF(2), arr), name="LT")


# ---------------------------------------------------------------------------
# Main cipher class
# ---------------------------------------------------------------------------
class SERPENT_CVL:
    r"""
    The CiVerLy implementation of the Serpent block cipher.

    Serpent is a 32-round SP-network operating on four 32-bit words,
    giving a block size of 128 bits. The cipher consists of:

    - An initial permutation (IP)
    - 32 rounds, each applying: key mixing XOR, S-box layer, linear
      transformation (except the last round, which replaces LT by an
      additional key XOR)
    - A final permutation (FP)

    INPUT::

        - ``R`` -- integer; Number of rounds (default: ``32``). Mutually
          exclusive with an explicit ``(start, end)`` range.

        - ``rks`` -- list (optional); Specifies the round key values.
          Must have length ``R+1`` (33 keys for full-round Serpent).
          Defaults to all zeros. May not be combined with ``master_key``.

        - ``master_key`` -- integer (optional); A master key from which round
          keys are derived via :func:`serpent_key_schedule`. May not be
          combined with ``rks``.

        - ``keylen`` -- integer (default: ``128``); Length of ``master_key`` in bits.

        - ``name`` -- string (optional); The name of the cipher.

        - ``start`` -- integer (default: ``0``); The first Serpent round to
          include, indexed from 0. Use this to construct a reduced-round cipher
          starting at a later round (e.g. ``start=4`` for an attack on rounds
          4--10). Must be provided together with ``end``.

        - ``end`` -- integer (optional); The last Serpent round to include,
          indexed from 0. If given, ``R`` is computed as ``end - start + 1``.

    EXAMPLES::

        Verify encryption with the NESSIE test vectors
        (see https://biham.cs.technion.ac.il/Reports/Serpent/)
        with KEYSIZE=128, KEY=0 from ``ecb_tbl_precomputed.txt``::

            sage: from civerly.cipher_implementations.serpent import SERPENT_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: serpent = SERPENT_CVL(master_key=0, keylen=128)
            sage: pt1 = int('8ED77392F29990EDA7A3A3CE6F579DD2', 16)
            sage: hex(vec_to_int(serpent(int_to_vec(pt1, 128))))
            '0x2d99fd0696ced14886b0e88a968b28b2'
            sage: pt2 = int('8ED77392F29990EDA7A3A3CE90A8622D', 16)
            sage: hex(vec_to_int(serpent(int_to_vec(pt2, 128))))
            '0x2d118710a9ac549d932e1ab82eb07e71'
            sage: pt3 = int('8ED773920D666F12A7A3A3CE6F579DD2', 16)
            sage: hex(vec_to_int(serpent(int_to_vec(pt3, 128))))
            '0x18e7f7888133888b42b78653501bba41'

        Instantiate with a master key (round keys are derived automatically)::

            sage: serpent = SERPENT_CVL(R=1, master_key=0, keylen=128)
            sage: result = serpent(int_to_vec(0x0, 128))
            sage: vec_to_int(result) > 0
            True

        Construct a sliced version of the cipher (rounds 4-10).
        In this mode the internal data path is preserved: IP and FP are
        omitted because they lie outside the chosen range, and every selected
        round keeps its linear transformation (only the true final round, 31,
        would receive an extra key XOR instead).::

            sage: serpent = SERPENT_CVL(master_key=0, keylen=128, start=4, end=10)
            sage: result = serpent(int_to_vec(0x0, 128))
            sage: vec_to_int(result) > 0
            True
            sage: names = [n.name for n in serpent.nodes]
            sage: 'IP' in names
            False
            sage: 'FP' in names
            False
            sage: names.count('LT')
            7

        Backward-compatible reduced-round cipher (R=7) still ends with the
        final key XOR and FP::

            sage: serpent = SERPENT_CVL(master_key=0, keylen=128, R=7)
            sage: names = [n.name for n in serpent.nodes]
            sage: 'FP' in names
            True
            sage: names.count('LT')
            6

        ``R`` and ``(start, end)`` are mutually exclusive, and ``start``/``end``
        must be supplied together::

            sage: SERPENT_CVL(R=7, start=4, end=10)
            Traceback (most recent call last):
            ...
            ValueError: R cannot be combined with an explicit (start, end) range
            sage: SERPENT_CVL(start=4)
            Traceback (most recent call last):
            ...
            ValueError: start and end must be provided together

        ``master_key`` and ``rks`` are mutually exclusive::

            sage: SERPENT_CVL(master_key=0, rks=[0] * 34)
            Traceback (most recent call last):
            ...
            ValueError: master_key and rks are mutually exclusive

        Model the cipher with SAT::

            sage: # optional - cadical espresso
            sage: from civerly.cipher_implementations.serpent import SERPENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   serpent = SERPENT_CVL(R=3)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sat_solver=CADICAL_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       path=Path(tmpdir))
            ....:   serpent.analyse(model_options)
            ....:   trail = str(serpent.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            6884 variables and 19953 clauses were written to ...
            19
    """

    def __init__(
        self, R=32, rks=None, master_key=None, keylen=128, name=None, start=0, end=None
    ):
        if name is None:
            name = "SERPENT"

        if master_key is not None and rks is not None:
            raise ValueError("master_key and rks are mutually exclusive")

        explicit_slice = end is not None
        if explicit_slice and R != 32:
            raise ValueError("R cannot be combined with an explicit (start, end) range")
        if not explicit_slice and start != 0:
            raise ValueError("start and end must be provided together")
        if end is None:
            end = start + R - 1
        else:
            R = end - start + 1

        if R > 32:
            raise ValueError("Serpent only supports up to 32 rounds")
        if start < 0 or end >= 32:
            raise ValueError("Invalid round range for Serpent")

        # exact_slice: build the exact internal data path when the caller
        # explicitly requested a round range via (start, end).  In this mode
        # IP/FP are omitted unless the slice reaches the real cipher
        # boundaries, and every selected round keeps its original LT except
        # the true final round (31).
        exact_slice = explicit_slice

        if rks is None:
            if master_key is not None:
                full_rks = serpent_key_schedule(master_key, keylen=keylen, R=32)
                rks = full_rks[start : start + R + 1]
            else:
                rks = [0 for _ in range(R + 1)]
        elif len(rks) < R + 1:
            raise ValueError(f"Need at least {R + 1} round keys, got {len(rks)}")

        lt = _build_serpent_linear_layer()

        def make_sboxlayer(round_num):
            sbox_idx = round_num % 8
            sboxlayer = SBoxCipher(128, 128, name=f"SBoxLayer_R{round_num}")
            output_edges = []
            for n in range(32):
                in_pos = [127 - (4 * n + k) for k in range(4)]
                sbox = SBox_CVL(
                    SERPENT_SBOXES[sbox_idx], name=f"S{sbox_idx}_R{round_num}_{n}"
                )
                node = sboxlayer.add_subcipher(
                    sbox, [(sboxlayer.IN, (in_pos[3 - k], k)) for k in range(4)]
                )
                output_edges.extend([(node, (k, in_pos[3 - k])) for k in range(4)])
            sboxlayer.add_output(output_edges)
            return sboxlayer

        cipher = SBoxCipher(128, 128, name=name)

        # Initial permutation: standard -> standard-permuted (bitslice)
        if not exact_slice or start == 0:
            ip = PermuteLayer_CVL(FP_TABLE, name="IP")
            current = cipher.add_subcipher(
                ip, [(cipher.IN, (i, i)) for i in range(128)]
            )
        else:
            current = cipher.IN

        for r in range(R):
            round_num = start + r
            # Key addition
            key_add = RoundkeyXOR_CVL(128, rks[r], name=f"K{round_num}")
            current = cipher.add_subcipher(
                key_add, [(current, (i, i)) for i in range(128)]
            )

            # S-box layer
            sboxlayer = make_sboxlayer(round_num)
            current = cipher.add_subcipher(
                sboxlayer, [(current, (i, i)) for i in range(128)]
            )

            if r == R - 1:
                if exact_slice and round_num == 31:
                    # True final round of Serpent: extra key XOR
                    key_final = RoundkeyXOR_CVL(128, rks[R], name=f"K{round_num + 1}")
                    current = cipher.add_subcipher(
                        key_final, [(current, (i, i)) for i in range(128)]
                    )
                elif exact_slice:
                    # Internal round in an exact slice: keep LT
                    current = cipher.add_subcipher(
                        lt, [(current, (i, i)) for i in range(128)]
                    )
                else:
                    # Reduced-round mode: last round uses key XOR instead of LT
                    key_final = RoundkeyXOR_CVL(128, rks[R], name=f"K{round_num + 1}")
                    current = cipher.add_subcipher(
                        key_final, [(current, (i, i)) for i in range(128)]
                    )
            else:
                # Linear transformation
                current = cipher.add_subcipher(
                    lt, [(current, (i, i)) for i in range(128)]
                )

        # Final permutation: standard-permuted -> standard
        if not exact_slice or end == 31:
            fp = PermuteLayer_CVL(IP_TABLE, name="FP")
            current = cipher.add_subcipher(fp, [(current, (i, i)) for i in range(128)])

        cipher.add_output([(current, (i, i)) for i in range(128)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
