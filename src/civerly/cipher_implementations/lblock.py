from sage.crypto.sbox import SBox

from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    XOR_CVL,
    ConstXOR_CVL,
    PermuteLayer_CVL,
    RotateLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule
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


def _make_ks_step(i):
    r"""
    One LBlock key-schedule update as an ``SBoxCipher(80, 80)``.

    In the 80-bit vector, bit 0 is the MSB, i.e. ``k79`` sits at index 0 and
    ``k_j`` at index ``79 - j``. The step computes

    (a) ``K = K <<< 29``,
    (b) ``[k79k78k77k76] = s9([k79k78k77k76])`` and
        ``[k75k74k73k72] = s8([k75k74k73k72])``,
    (c) ``[k50k49k48k47k46] ^= [i+1]_2``.
    """
    step = SBoxCipher(80, 80, name=f"KS-step-{i}")
    node_rot = step.add_subcipher(
        RotateLayer_CVL(80, 29, word_coarseness=1, name="rot29"),
        [(step.IN, (j, j)) for j in range(80)],
    )
    node_s9 = step.add_subcipher(
        SBox_CVL(_SBOXES[9], name="ks_s9"), [(node_rot, (j, j)) for j in range(4)]
    )
    node_s8 = step.add_subcipher(
        SBox_CVL(_SBOXES[8], name="ks_s8"),
        [(node_rot, (4 + j, j)) for j in range(4)],
    )
    # k50..k46 are vector bits 29..33 (k50 = MSB of the counter)
    node_c = step.add_subcipher(
        ConstXOR_CVL(5, (i + 1) & 0x1F, name=f"ks_counter_{i + 1}"),
        [(node_rot, (29 + j, j)) for j in range(5)],
    )
    step.add_output(
        [(node_s9, (j, j)) for j in range(4)]
        + [(node_s8, (j, 4 + j)) for j in range(4)]
        + [(node_rot, (j, j)) for j in range(8, 29)]
        + [(node_c, (j, 29 + j)) for j in range(5)]
        + [(node_rot, (j, j)) for j in range(34, 80)]
    )
    return step


class LBLOCK_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=32, name="LBlock-KeySchedule"):
        r"""
        LBlock key schedule [Wu11] as a CiVerLy DAG.

        Takes an 80-bit master key ``K = k79 k78 ... k0`` and expands it into
        ``R`` round keys of 32 bits each. Round key ``K_0`` is the leftmost 32
        bits of ``K``; for ``i = 1, ..., R - 1`` the key register is updated by

        (a) ``K = K <<< 29``,
        (b) ``[k79k78k77k76] = s9([k79k78k77k76])`` and
            ``[k75k74k73k72] = s8([k75k74k73k72])``,
        (c) ``[k50k49k48k47k46] = [k50k49k48k47k46] ^ [i]_2``,

        and ``K_i`` is the leftmost 32 bits of the updated register.

        INPUT:

            - ``R`` -- integer (default: ``32``); number of rounds, i.e. the
              number of round keys (same meaning as in :class:`LBLOCK_CVL`).

            - ``name`` -- string (default: ``"LBlock-KeySchedule"``); name.

        EXAMPLES::

            sage: from civerly.cipher_implementations.lblock import (
            ....:   LBLOCK_KeySchedule_CVL)
            sage: ks = LBLOCK_KeySchedule_CVL()
            sage: rks = ks(0x0)
            sage: len(rks)
            32
            sage: [hex(k) for k in rks[:4]]
            ['0x0', '0xb8000000', '0xbb000000', '0x580002e0']
            sage: ks.input_length, ks.output_length
            (80, 1024)

        TESTS:

        The round keys for ``R`` rounds are a prefix of those for 32 rounds::

            sage: from civerly.cipher_implementations.lblock import (
            ....:   LBLOCK_KeySchedule_CVL)
            sage: k = 0x0123456789abcdeffedc
            sage: LBLOCK_KeySchedule_CVL(R=5)(k) == LBLOCK_KeySchedule_CVL()(k)[:5]
            True
            sage: LBLOCK_KeySchedule_CVL(R=1)(k) == [0x01234567]
            True
        """
        super().__init__(80, 32 * R, name=name)

        output_edges = [(self.IN, (j, j)) for j in range(32)]
        node = self.IN
        for i in range(R - 1):
            node = self.add_subcipher(
                _make_ks_step(i), [(node, (j, j)) for j in range(80)]
            )
            output_edges += [(node, (j, 32 * (i + 1) + j)) for j in range(32)]
        self.add_output(output_edges)

    def eval(self, k):
        r"""
        Expand master key ``k`` into a list of ``R`` 32-bit round-key integers.

        INPUT:

            - ``k`` -- integer; 80-bit master key.

        OUTPUT: List of ``R`` integers, round key 0 first.
        """
        from civerly.util import int_to_vec, vec_to_int

        bits = Cipher.eval(self, int_to_vec(k, self.input_length))
        return [
            vec_to_int(bits[32 * i : 32 * (i + 1)])
            for i in range(self.output_length // 32)
        ]


class LBLOCK_CVL(CipherImplementation_CVL, SBoxCipher):
    def __init__(self, R=32, key_schedule=None, key=None, name="LBlock"):
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

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass :class:`LBLOCK_KeySchedule_CVL` to use
              the real LBlock key schedule, or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (``R`` of them, 32 bits each). Defaults to
              ``None`` (no key schedule, all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The 80-bit
              master key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first).

            - ``name`` -- string (default: ``"LBlock"``); cipher name.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Test vectors from the LBlock specification (https://eprint.iacr.org/2011/345, App. I)::

            sage: from civerly.cipher_implementations.lblock \
            ....:   import LBLOCK_CVL, LBLOCK_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = LBLOCK_CVL(
            ....:   R=32, key_schedule=LBLOCK_KeySchedule_CVL(R=32), key=0x0)
            sage: hex(vec_to_int(cipher(int_to_vec(0x0, 64))))
            '0xc218185308e75bcd'
            sage: cipher.set_round_keys(0x0123456789abcdeffedc)
            sage: hex(vec_to_int(cipher(int_to_vec(0x0123456789abcdef, 64))))
            '0x4b7179d8ebee0c26'

        Explicit round keys can be passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: rks = LBLOCK_KeySchedule_CVL(R=32)(0x0123456789abcdeffedc)
            sage: cipher = LBLOCK_CVL(
            ....:   R=32, key_schedule=DefaultKeySchedule_CVL(32, 32), key=rks)
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
        super().__init__(64, 64, R=R, key_schedule=key_schedule, key=key, name=name)

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
        node = self.IN
        for _ in range(self.R):
            node = self.add_subcipher(lblock_round, [(node, (i, i)) for i in range(64)])

        # After 32 rounds the state is (X33, X32).
        # The ciphertext must be X32 || X33, so we swap the halves.
        final_swap = PermuteLayer_CVL(
            list(range(32, 64)) + list(range(32)), name="FinalSwap"
        )
        node = self.add_subcipher(final_swap, [(node, (i, i)) for i in range(64)])
        self.add_output([(node, (i, i)) for i in range(64)])

        self._rk_components = [self.nodes[r + 1].nodes[node_rk] for r in range(self.R)]

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
