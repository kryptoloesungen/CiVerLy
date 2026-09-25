from sage.crypto.sbox import SBox

from civerly.component import (
    XOR_CVL,
    PermuteLayer_CVL,
    RotateLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.sboxcipher import SBoxCipher

# S-boxes used in LBlock (s0 through s9)
_SBOX_TABLES = [
    [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],  # s0
    [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3],  # s1
    [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10],  # s2
    [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1],  # s3
    [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3],  # s4
    [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5],  # s5
    [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2],  # s6
    [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6],  # s7
    [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3],  # s8
    [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6],  # s9
]

# Build reusable Sage SBox objects
_SBOXES = [SBox(t) for t in _SBOX_TABLES]


def _build_sbox_layer():
    r"""
    Build the LBlock S-box layer (32-bit in, 32-bit out).

    In the 32-bit vector used by CiVerLy, bit 0 is the MSB.  The eight
    4-bit S-boxes are wired so that the upper nibble (vector bits 0--3)
    is processed by ``s7`` and the lower nibble (bits 28--31) by ``s0``,
    matching the specification ``Z_i = s_i(Y_i)``.
    """
    sboxlayer = SBoxCipher(32, 32, name="SBoxLayer")
    for i in range(8):
        # s0 sits at the least-significant nibble (vector bits 28--31),
        # s7 at the most-significant nibble (vector bits 0--3).
        src_start = 28 - 4 * i
        sbox = SBox_CVL(_SBOXES[i], name=f"s{i}")
        node = sboxlayer.add_subcipher(
            sbox,
            [(sboxlayer.IN, (src_start + j, j)) for j in range(4)],
        )
        sboxlayer.add_output([(node, (j, src_start + j)) for j in range(4)])
    return sboxlayer


def lblock_key_schedule(key, rounds=32):
    r"""
    Generate the 32-bit round keys for LBlock from an 80-bit master key.

    INPUT:

        - ``key`` -- integer; the 80-bit master key.

        - ``rounds`` -- integer (default: ``32``); number of rounds.

    OUTPUT: A list of ``rounds`` 32-bit round-key integers.

    EXAMPLES::

        sage: from civerly.cipher_implementations.lblock import lblock_key_schedule
        sage: rks = lblock_key_schedule(0x0)
        sage: [hex(k) for k in rks[:4]]
        ['0x0', '0xb8000000', '0xbb000000', '0x580002e0']
    """
    K = key & ((1 << 80) - 1)
    rks = []
    for i in range(rounds):
        # output leftmost 32 bits as round key
        rks.append((K >> 48) & 0xFFFFFFFF)
        # (a) rotate left by 29
        K = ((K << 29) & ((1 << 80) - 1)) | (K >> (80 - 29))
        # (b) s9 on the top nibble, s8 on the next nibble
        nibble9 = (K >> 76) & 0xF
        nibble8 = (K >> 72) & 0xF
        K = (
            (K & ~((0xF << 76) | (0xF << 72)))
            | (_SBOX_TABLES[9][nibble9] << 76)
            | (_SBOX_TABLES[8][nibble8] << 72)
        )
        # (c) XOR counter [i+1]_2 into bits k50..k46
        counter = (i + 1) & 0x1F
        k_bits = (K >> 46) & 0x1F
        k_bits ^= counter
        K = (K & ~(0x1F << 46)) | (k_bits << 46)
    return rks


class LBLOCK_CVL:
    def __init__(self, R=32, rks=None, name=None):
        r"""
        The CiVerLy implementation of LBlock [Wu11].

        LBlock is a 64-bit block cipher with an 80-bit key.  It is a
        32-round variant Feistel network.  The round function ``F``
        consists of a key addition, eight parallel 4-bit S-boxes
        (``s0``--``s7``), and a word-wise permutation ``P``.
        Each Feistel step computes

        .. MATH::

            X_i = F(X_{i-1},K_{i-1}) \oplus (X_{i-2} \lll 8),

        and the ciphertext is ``C = X_{32} \| X_{33}``.

        INPUT:

            - ``R`` -- integer (default: ``32``); number of rounds.

            - ``rks`` -- list (optional); ``R`` many 32-bit round keys.
              Defaults to all-zero keys.

            - ``name`` -- string (optional); cipher name.

        EXAMPLES:

        Test vectors from the LBlock specification (https://eprint.iacr.org/2011/345, App. I)::

            sage: from civerly.cipher_implementations.lblock \
            ....:   import LBLOCK_CVL, lblock_key_schedule
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = lblock_key_schedule(0x0)
            sage: cipher = LBLOCK_CVL(R=32, rks=rks)
            sage: hex(vec_to_int(cipher(int_to_vec(0x0, 64))))
            '0xc218185308e75bcd'
            sage: rks = lblock_key_schedule(0x0123456789abcdeffedc)
            sage: cipher = LBLOCK_CVL(R=32, rks=rks)
            sage: hex(vec_to_int(cipher(int_to_vec(0x0123456789abcdef, 64))))
            '0x4b7179d8ebee0c26'

        Model the cipher with SAT (verifying https://eprint.iacr.org/2011/345, Table 2)::

            sage: from civerly.cipher_implementations.lblock \
            ....:   import LBLOCK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat espresso
            ....:   cipher = LBLOCK_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(0, 10),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            Using existing file ...
            Using existing file ...
            4320 variables and 9617 clauses were written to ...
            6

        Model the cipher with MILP::

            sage: from civerly.cipher_implementations.lblock \
            ....:   import LBLOCK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip  # optional - espresso
            ....:   cipher = LBLOCK_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            4320 variables and 5089 constraints were written to ...
            6
        """
        if rks is None:
            rks = [0x0 for _ in range(R)]
        if name is None:
            name = "LBlock"

        # Reusable layers
        sboxlayer = _build_sbox_layer()
        p_perm = PermuteLayer_CVL([2, 0, 3, 1, 6, 4, 7, 5], word_coarseness=4, name="P")
        rot = RotateLayer_CVL(32, 8, word_coarseness=1, name="rot")
        xor = XOR_CVL(32, name="xor")
        rk = RoundkeyXOR_CVL(32, 0x0, name="rk")

        # One LBlock round: (L,R) -> (T,L) with T = F(L,K) xor (R <<< 8)
        lblock_round = SBoxCipher(64, 64, name="LBlock_round")
        node_rk = lblock_round.add_subcipher(
            rk, [(lblock_round.IN, (i, i)) for i in range(32)]
        )
        node_s = lblock_round.add_subcipher(
            sboxlayer, [(node_rk, (i, i)) for i in range(32)]
        )
        node_p = lblock_round.add_subcipher(
            p_perm, [(node_s, (i, i)) for i in range(32)]
        )
        node_rot = lblock_round.add_subcipher(
            rot, [(lblock_round.IN, (i + 32, i)) for i in range(32)]
        )
        node_xor = lblock_round.add_subcipher(
            xor,
            [(node_p, (i, i)) for i in range(32)]
            + [(node_rot, (i, i + 32)) for i in range(32)],
        )
        # new left = xor result, new right = old left
        lblock_round.add_output([(node_xor, (i, i)) for i in range(32)])
        lblock_round.add_output([(lblock_round.IN, (i, i + 32)) for i in range(32)])

        # Full cipher
        cipher = SBoxCipher(64, 64, name=name)
        node = cipher.IN
        for r in range(R):
            lblock_round.nodes[node_rk].const = rks[r]
            node = cipher.add_subcipher(
                lblock_round, [(node, (i, i)) for i in range(64)]
            )

        # After 32 rounds the state is (X33, X32).
        # The ciphertext must be X32 || X33, so we swap the halves.
        final_swap = PermuteLayer_CVL(
            list(range(32, 64)) + list(range(32)), name="FinalSwap"
        )
        node = cipher.add_subcipher(final_swap, [(node, (i, i)) for i in range(64)])
        cipher.add_output([(node, (i, i)) for i in range(64)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
