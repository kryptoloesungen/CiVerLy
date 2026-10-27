r"""
Implementation of the Serpent block cipher.

Serpent is a 32-round SP-network operating on four 32-bit words,
giving a block size of 128 bits. It uses 8 different 4-bit S-boxes
applied in parallel 32 times per round.

The implementation follows the standard Serpent description from the
original specification, including the initial permutation (IP) and
final permutation (FP).

EXAMPLES::

    sage: from civerly.cipher_implementations.serpent \
    ....:   import SERPENT_CVL, SERPENT_KeySchedule_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: serpent = SERPENT_CVL(key_schedule=SERPENT_KeySchedule_CVL(), key=0)
    sage: pt = int('8ED77392F29990EDA7A3A3CE6F579DD2', 16)
    sage: ct = vec_to_int(serpent(int_to_vec(pt, 128)))
    sage: hex(ct)
    '0x2d99fd0696ced14886b0e88a968b28b2'

"""

from sage.crypto.sbox import SBox as SBox_sage
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    C_CVL,
    XOR_CVL,
    ConstXOR_CVL,
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RotateLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule
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

        sage: from civerly.cipher_implementations.serpent \
        ....:   import _build_serpent_linear_layer
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
# Key schedule
# ---------------------------------------------------------------------------
class SERPENT_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=32, keylen=128, name="SERPENT-KeySchedule"):
        r"""
        The Serpent key schedule as a CiVerLy DAG.

        The ``keylen``-bit master key is padded to 256 bits by appending a
        single ``1`` bit followed by zeros (above the most significant key
        bit), and split into eight 32-bit prekey words
        ``w_{-8}, ..., w_{-1}`` (``w_{-8}`` being the least significant word).
        The prekeys are expanded by the affine recurrence

        .. MATH::

            w_i = (w_{i-8} \oplus w_{i-5} \oplus w_{i-3} \oplus w_{i-1}
                   \oplus \phi \oplus i) \lll 11,

        with :math:`\phi` = ``0x9e3779b9``. Round key ``K_i`` is obtained
        by applying S-box ``S_{(3 - i) mod 8}`` in bitslice mode to the words
        ``w_{4i}, ..., w_{4i+3}`` and then the initial permutation (IP), i.e.
        it is the standard-mode subkey ``KHat_i``.

        The DAG consists of ``R + 1`` steps; step ``i`` takes the 256-bit
        window ``w_{4i-8} || ... || w_{4i-1}`` and outputs the next window
        ``w_{4i-4} || ... || w_{4i+3}`` together with round key ``K_i``. Each
        step consists of four prekey-word sub-ciphers (``XOR_CVL``,
        ``ConstXOR_CVL``, ``RotateLayer_CVL``), a layer of 32 ``SBox_CVL``
        and a ``PermuteLayer_CVL`` for IP. The constant padding bits are
        produced by a ``C_CVL`` node.

        The output are the ``R + 1`` round keys of :class:`SERPENT_CVL` with
        ``R`` rounds, in the order of its round-key components, so an instance
        can be passed as ``key_schedule`` to :class:`SERPENT_CVL`.

        INPUT:

            - ``R`` -- integer (default: ``32``); Number of rounds of the
              corresponding :class:`SERPENT_CVL`. The key schedule outputs
              ``R + 1`` round keys of 128 bits each.

            - ``keylen`` -- integer (default: ``128``); The master key length
              in bits, ``1 <= keylen <= 256``.

            - ``name`` -- string (default: ``"SERPENT-KeySchedule"``); The
              name of the key schedule.

        EXAMPLES::

            sage: from civerly.cipher_implementations.serpent \
            ....:   import SERPENT_KeySchedule_CVL
            sage: ks = SERPENT_KeySchedule_CVL()
            sage: (ks.input_length, ks.output_length)
            (128, 4224)
            sage: rks = ks(0)
            sage: len(rks)
            33
            sage: hex(rks[0])
            '0xe5749bf3e92d49bf78ad11abf74966b4'
            sage: hex(rks[1])
            '0x3e602208886902fcc781325fc60cbddc'
            sage: hex(rks[2])
            '0x7d595686772092219d7070d223d44f82'

            sage: rks = SERPENT_KeySchedule_CVL(R=2, keylen=256)(0)
            sage: len(rks)
            3
            sage: hex(rks[0])
            '0xe5749bf3ef2d49bf78ad41abf7496624'
            sage: hex(rks[1])
            '0x3e602208726902fcc7d3c25fc60cb03c'
            sage: hex(rks[2])
            '0x7d59567c272092219b4870d223d4d4a2'

        TESTS:

        Verify with the test vector from the NESSIE suite (128-bit key)::

            sage: from civerly.cipher_implementations.serpent \
            ....:   import SERPENT_KeySchedule_CVL
            sage: key = int("80000000000000000000000000000000", 16)
            sage: rks = SERPENT_KeySchedule_CVL(R=2)(key)
            sage: hex(rks[0])
            '0xe5749bf3e90d49bf78adf0abf74966be'
            sage: hex(rks[1])
            '0x3e602208d1a902fcc78b725fc60cbd79'
            sage: hex(rks[2])
            '0x7d59568107e092219db790d223d4ab69'

        Invalid parameters are rejected::

            sage: SERPENT_KeySchedule_CVL(R=33)
            Traceback (most recent call last):
            ...
            ValueError: Serpent only supports up to 32 rounds
            sage: SERPENT_KeySchedule_CVL(keylen=257)
            Traceback (most recent call last):
            ...
            ValueError: Key length must be at most 256 bits
        """
        if keylen > 256:
            raise ValueError("Key length must be at most 256 bits")
        if keylen < 1:
            raise ValueError("Key length must be positive")
        if R > 32:
            raise ValueError("Serpent only supports up to 32 rounds")

        super().__init__(keylen, 128 * (R + 1), name=name)
        self._R = R

        # The 256-bit window w_{base} || ... || w_{base+7} is laid out as the
        # integer sum(w_{base+s} << 32 * s), i.e. slot s occupies the
        # (MSB-first) bits 32 * (7 - s) .. 32 * (7 - s) + 31. The padded key
        # is exactly the initial window w_{-8} .. w_{-1}: the key occupies the
        # last ``keylen`` bits, preceded by the padding constant 0...01.
        if keylen < 256:
            pad = self.add_subcipher(C_CVL(256 - keylen, 1, name="KeyPadding"), [])
            window = [(pad, j) for j in range(256 - keylen)]
            window += [(self.IN, j) for j in range(keylen)]
        else:
            window = [(self.IN, j) for j in range(256)]

        # The permutation layers are built once and shared by all steps
        # (``add_subcipher`` copies them), as their construction is costly.
        rot = RotateLayer_CVL(32, 11, name="ROTL11")
        ip_perm = [0] * 128
        for p in range(128):
            ip_perm[127 - IP_TABLE[p]] = 127 - p
        ip = PermuteLayer_CVL(ip_perm, name="KS-IP")

        output_edges = []
        for i in range(R + 1):
            step = self.add_subcipher(
                self._make_ks_step(i, rot, ip),
                [(src, (j, k)) for k, (src, j) in enumerate(window)],
            )
            window = [(step, j) for j in range(256)]
            output_edges += [(step, (256 + j, 128 * i + j)) for j in range(128)]

        self.add_output(output_edges)

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into the list of ``R + 1`` round-key integers.

        INPUT:

            - ``master_key`` -- integer; The ``keylen``-bit master key.

        OUTPUT: List of ``R + 1`` 128-bit integers ``K_0, ..., K_R``.
        """
        from civerly.util import int_to_vec, vec_to_int

        bits = Cipher.eval(self, int_to_vec(master_key, self.input_length))
        return [vec_to_int(bits[128 * i : 128 * (i + 1)]) for i in range(self._R + 1)]

    @staticmethod
    def _make_prekey_word(index, rot):
        r"""
        One prekey word ``w_index`` as an ``SBoxCipher(128 -> 32)``; ``rot``
        is the rotation-by-11 layer.

        Takes ``w_{index-8} || w_{index-5} || w_{index-3} || w_{index-1}`` and
        outputs ``(w_{index-8} ^ w_{index-5} ^ w_{index-3} ^ w_{index-1}
        ^ phi ^ index) <<< 11``.
        """
        word = SBoxCipher(128, 32, name=f"w{index}")
        node = word.add_subcipher(
            XOR_CVL(32, name=f"w{index}_XOR0"),
            [(word.IN, (j, j)) for j in range(64)],
        )
        for t in (2, 3):
            node = word.add_subcipher(
                XOR_CVL(32, name=f"w{index}_XOR{t - 1}"),
                [(node, (j, j)) for j in range(32)]
                + [(word.IN, (32 * t + j, 32 + j)) for j in range(32)],
            )
        node = word.add_subcipher(
            ConstXOR_CVL(32, PHI ^ index, name=f"w{index}_const"),
            [(node, (j, j)) for j in range(32)],
        )
        node = word.add_subcipher(
            rot,
            [(node, (j, j)) for j in range(32)],
        )
        word.add_output([(node, (j, j)) for j in range(32)])
        return word

    @staticmethod
    def _make_ks_step(i, rot, ip):
        r"""
        Key-schedule step ``i`` as an ``SBoxCipher(256 -> 384)``; ``rot`` is
        the rotation-by-11 layer and ``ip`` the initial permutation layer.

        Input: the window ``w_{4i-8} .. w_{4i-1}``. Output: the next window
        ``w_{4i-4} .. w_{4i+3}`` (bits ``0 .. 255``), followed by round key
        ``K_i`` (bits ``256 .. 383``).
        """
        step = SBoxCipher(256, 384, name=f"KS-step{i}")

        def slot(s):
            # MSB-first offset of window slot s
            return 32 * (7 - s)

        # Sources of window slots 0 .. 11: slots 0 .. 7 are the input,
        # slots 8 .. 11 the newly computed words w_{4i} .. w_{4i+3}.
        sources = [(step.IN, slot(s)) for s in range(8)]
        for c in range(4):
            srcs = [sources[c + d] for d in (0, 3, 5, 7)]
            node = step.add_subcipher(
                SERPENT_KeySchedule_CVL._make_prekey_word(4 * i + c, rot),
                [
                    (a, (off + j, 32 * t + j))
                    for t, (a, off) in enumerate(srcs)
                    for j in range(32)
                ],
            )
            sources.append((node, 0))

        # Bitslice S-box S_{(3 - i) mod 8}: nibble j consists of bit j (LSB
        # first) of w_{4i+3}, ..., w_{4i} (MSB first), and its output bit c
        # is bit j of the bitslice word c, i.e. bit 32 * c + j of the packed
        # 128-bit value w'_{4i+3} || ... || w'_{4i}.
        sbox_idx = (3 - i) % 8
        sboxlayer = SBoxCipher(128, 128, name=f"KS-SBoxLayer{i}")
        sb_out = []
        for j in range(32):
            sb = sboxlayer.add_subcipher(
                SBox_CVL(SERPENT_SBOXES[sbox_idx], name=f"KS-S{sbox_idx}_{i}_{j}"),
                [(sboxlayer.IN, (32 * k + 31 - j, k)) for k in range(4)],
            )
            sb_out += [(sb, (k, 32 * k + 31 - j)) for k in range(4)]
        sboxlayer.add_output(sb_out)
        node_sb = step.add_subcipher(
            sboxlayer,
            [
                (a, (off + j, 32 * (3 - c) + j))
                for c, (a, off) in enumerate(sources[8:])
                for j in range(32)
            ],
        )

        # Initial permutation: KHat bit p is bit IP_TABLE[p] of the packed
        # bitslice value (LSB-first numbering).
        node_ip = step.add_subcipher(
            ip,
            [(node_sb, (j, j)) for j in range(128)],
        )

        out = []
        for s in range(8):
            a, off = sources[s + 4]
            out += [(a, (off + j, slot(s) + j)) for j in range(32)]
        out += [(node_ip, (j, 256 + j)) for j in range(128)]
        step.add_output(out)
        return step


# ---------------------------------------------------------------------------
# Main cipher class
# ---------------------------------------------------------------------------
class SERPENT_CVL(CipherImplementation_CVL, SBoxCipher):
    def __init__(self, R=32, key_schedule=None, key=None, name="SERPENT"):
        r"""
        The CiVerLy implementation of the Serpent block cipher.

        Serpent is a 32-round SP-network operating on four 32-bit words,
        giving a block size of 128 bits. The cipher consists of:

        - An initial permutation (IP)
        - 32 rounds, each applying: key mixing XOR, S-box layer, linear
          transformation (except the last round, which replaces LT by an
          additional key XOR)
        - A final permutation (FP)

        INPUT:

            - ``R`` -- integer (default: ``32``); Number of rounds, starting
              from round 0. A reduced-round cipher ends with the final key XOR
              (instead of the linear transformation) and FP.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass an instance of
              :class:`SERPENT_KeySchedule_CVL` (with the same ``R``) to use the
              real Serpent key schedule (select the key length via its
              ``keylen`` argument), or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (``R + 1`` of them, 128 bits each).
              Defaults to ``None`` (no key schedule, all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The master
              key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first).

            - ``name`` -- string (default: ``"SERPENT"``); The name of the
              cipher.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Verify encryption with the NESSIE test vectors
        (see https://biham.cs.technion.ac.il/Reports/Serpent/)
        with KEYSIZE=128, KEY=0 from ``ecb_tbl_precomputed.txt``::

            sage: from civerly.cipher_implementations.serpent \
            ....:   import SERPENT_CVL, SERPENT_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: ks = SERPENT_KeySchedule_CVL()
            sage: serpent = SERPENT_CVL(key_schedule=ks, key=0)
            sage: pt1 = int('8ED77392F29990EDA7A3A3CE6F579DD2', 16)
            sage: hex(vec_to_int(serpent(int_to_vec(pt1, 128))))
            '0x2d99fd0696ced14886b0e88a968b28b2'
            sage: pt2 = int('8ED77392F29990EDA7A3A3CE90A8622D', 16)
            sage: hex(vec_to_int(serpent(int_to_vec(pt2, 128))))
            '0x2d118710a9ac549d932e1ab82eb07e71'
            sage: pt3 = int('8ED773920D666F12A7A3A3CE6F579DD2', 16)
            sage: hex(vec_to_int(serpent(int_to_vec(pt3, 128))))
            '0x18e7f7888133888b42b78653501bba41'

        Explicit round keys can be passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: rks = ks(0)
            sage: serpent = SERPENT_CVL(
            ....:   key_schedule=DefaultKeySchedule_CVL(128, 33), key=rks)
            sage: hex(vec_to_int(serpent(int_to_vec(pt1, 128))))
            '0x2d99fd0696ced14886b0e88a968b28b2'

        Other key lengths are selected via ``keylen``::

            sage: ks256 = SERPENT_KeySchedule_CVL(keylen=256)
            sage: serpent = SERPENT_CVL(key_schedule=ks256, key=0)
            sage: ct = serpent(int_to_vec(pt1, 128))
            sage: rks = ks256(0)
            sage: serpent = SERPENT_CVL(
            ....:   key_schedule=DefaultKeySchedule_CVL(128, 33), key=rks)
            sage: serpent(int_to_vec(pt1, 128)) == ct
            True

        Instantiate with a master key (round keys are derived automatically)::

            sage: ks1 = SERPENT_KeySchedule_CVL(R=1)
            sage: serpent = SERPENT_CVL(R=1, key_schedule=ks1, key=0)
            sage: result = serpent(int_to_vec(0x0, 128))
            sage: vec_to_int(result) > 0
            True

        A reduced-round cipher (R=7) ends with the final key XOR and FP::

            sage: ks7 = SERPENT_KeySchedule_CVL(R=7)
            sage: serpent = SERPENT_CVL(R=7, key_schedule=ks7, key=0)
            sage: names = [n.name for n in serpent.nodes]
            sage: 'FP' in names
            True
            sage: names.count('LT')
            6

        At most 32 rounds are supported::

            sage: SERPENT_CVL(R=33)
            Traceback (most recent call last):
            ...
            ValueError: Serpent only supports up to 32 rounds

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
        if R > 32:
            raise ValueError("Serpent only supports up to 32 rounds")

        super().__init__(128, 128, R=R, key_schedule=key_schedule, key=key, name=name)

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

        rk_nodes = []

        # Initial permutation: standard -> standard-permuted (bitslice)
        ip = PermuteLayer_CVL(FP_TABLE, name="IP")
        current = self.add_subcipher(ip, [(self.IN, (i, i)) for i in range(128)])

        for round_num in range(self.R):
            # Key addition
            key_add = RoundkeyXOR_CVL(128, 0x0, name=f"K{round_num}")
            current = self.add_subcipher(
                key_add, [(current, (i, i)) for i in range(128)]
            )
            rk_nodes.append(current)

            # S-box layer
            sboxlayer = make_sboxlayer(round_num)
            current = self.add_subcipher(
                sboxlayer, [(current, (i, i)) for i in range(128)]
            )

            if round_num == self.R - 1:
                # Last round: extra key XOR instead of LT
                key_final = RoundkeyXOR_CVL(128, 0x0, name=f"K{round_num + 1}")
                current = self.add_subcipher(
                    key_final, [(current, (i, i)) for i in range(128)]
                )
                rk_nodes.append(current)
            else:
                # Linear transformation
                current = self.add_subcipher(
                    lt, [(current, (i, i)) for i in range(128)]
                )

        # Final permutation: standard-permuted -> standard
        fp = PermuteLayer_CVL(IP_TABLE, name="FP")
        current = self.add_subcipher(fp, [(current, (i, i)) for i in range(128)])

        self.add_output([(current, (i, i)) for i in range(128)])

        self._rk_components = [self.nodes[n] for n in rk_nodes]

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
