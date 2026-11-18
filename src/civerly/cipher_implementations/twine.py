from sage.crypto.sbox import SBox

from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    XOR_CVL,
    ConstXOR_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule
from civerly.util import int_to_vec, vec_to_int
from civerly.wordsboxcipher import WordSBoxCipher

_SBOX_TABLE = (
    0xC, 0x0, 0xF, 0xA, 0x2, 0xB, 0x9, 0x5,
    0x8, 0x3, 0xD, 0x7, 0x1, 0xE, 0x6, 0x4,
)  # fmt: skip

_PERMUTATION = (5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14)

_ROUND_CONSTANTS = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x23,
    0x05, 0x0A, 0x14, 0x28, 0x13, 0x26, 0x0F, 0x1E, 0x3C, 0x3B, 0x35, 0x29,
    0x11, 0x22, 0x07, 0x0E, 0x1C, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24,
)  # fmt: skip


# Positions of the eight round-key nibbles RK^0, ..., RK^7 in the key state.
_RK_NIBBLES = {
    80: (1, 3, 4, 6, 13, 14, 15, 16),
    128: (2, 3, 12, 15, 17, 18, 28, 31),
}

# (source, target) nibble pairs of ``WK[target] ^= S(WK[source])``.
_SBOX_PAIRS = {
    80: ((0, 1), (16, 4)),
    128: ((0, 1), (16, 4), (30, 23)),
}


class TWINE_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=36, key_size=80, name=None):
        r"""
        The TWINE key schedule (80-bit or 128-bit key) as a CiVerLy DAG.

        The master key is loaded into a state of ``key_size / 4`` nibbles
        ``WK_0 | WK_1 | ...`` (``WK_0`` most significant). Round key ``RK_0``
        is extracted from the initial state, and each of the ``R - 1`` key
        schedule steps updates the state (S-box XORs, round-constant XOR,
        nibble rotation) before the next round key is extracted.

        TWINE XORs a 32-bit round key ``RK_r = RK_r^0 \| ... \| RK_r^7`` into
        the eight even-indexed nibbles of the state in every round. As
        :class:`TWINE_CVL` uses one 4-bit round-key component per nibble,
        :meth:`eval` returns the round keys split into nibbles: the ``R``
        round keys (round key 0 first), each as its 8 nibbles (``RK_r^0``,
        i.e. the most significant nibble, first). This is the order of the
        round-key components of :class:`TWINE_CVL`.

        INPUT:

            - ``R`` -- integer (default: ``36``); Number of rounds of the
              cipher, i.e. number of 32-bit round keys (at most 36).

            - ``key_size`` -- integer (default: ``80``); Key size in bits,
              either ``80`` or ``128``.

            - ``name`` -- string (optional); Name of the key schedule.

        EXAMPLES::

            sage: from civerly.cipher_implementations.twine \
            ....:   import TWINE_KeySchedule_CVL
            sage: ks = TWINE_KeySchedule_CVL()
            sage: rk_nibbles = ks(0x00112233445566778899)
            sage: len(rk_nibbles)
            288
            sage: [hex(n) for n in rk_nibbles[:8]]
            ['0x0', '0x1', '0x2', '0x3', '0x6', '0x7', '0x7', '0x8']
            sage: "".join(f"{n:x}" for n in rk_nibbles[-8:])  # RK_35
            '3532006e'
            sage: ks = TWINE_KeySchedule_CVL(R=2, key_size=128)
            sage: (ks.input_length, ks.output_length)
            (128, 64)
            sage: "".join(f"{n:x}" for n in ks(0x00112233445566778899AABBCCDDEEFF))
            '116789ef3388abc0'
            sage: TWINE_KeySchedule_CVL(key_size=96)
            Traceback (most recent call last):
            ...
            ValueError: key_size must be 80 or 128, got 96
        """
        if key_size not in _RK_NIBBLES:
            raise ValueError(f"key_size must be 80 or 128, got {key_size}")
        if not 1 <= R <= len(_ROUND_CONSTANTS) + 1:
            raise ValueError(
                f"R must be between 1 and {len(_ROUND_CONSTANTS) + 1}, got {R}"
            )
        if name is None:
            name = f"TWINE-{key_size}-KeySchedule"
        super().__init__(key_size, 32 * R, name=name)
        self._key_size = key_size
        self._R = R

        rk_nibbles = _RK_NIBBLES[key_size]

        def rk_edges(src, r):
            return [
                (src, (4 * p + b, 32 * r + 4 * j + b))
                for j, p in enumerate(rk_nibbles)
                for b in range(4)
            ]

        output_edges = rk_edges(self.IN, 0)
        node = self.IN
        for r in range(1, R):
            node = self.add_subcipher(
                self._make_ks_step(key_size, _ROUND_CONSTANTS[r - 1], r),
                [(node, (i, i)) for i in range(key_size)],
            )
            output_edges += rk_edges(node, r)
        self.add_output(output_edges)

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into the round keys, as ``8 * R`` nibbles.

        INPUT:

            - ``master_key`` -- integer; The 80-bit or 128-bit master key.

        OUTPUT: A list of ``8 * R`` 4-bit integers, round key 0 first, each
        round key most significant nibble first.
        """
        bits = Cipher.eval(self, int_to_vec(master_key, self.input_length))
        return [
            vec_to_int(bits[4 * i : 4 * (i + 1)])
            for i in range(self.output_length // 4)
        ]

    @staticmethod
    def _make_ks_step(key_size, con, r):
        r"""
        One TWINE key schedule step as a :class:`WordSBoxCipher` on nibbles.

        For TWINE-80 (``N = 20`` nibbles)::

            WK_1 ^= S(WK_0);  WK_4 ^= S(WK_16)
            WK_7 ^= CON_H;    WK_19 ^= CON_L
            WK = WK_4 | ... | WK_{N-1} | WK_1 | WK_2 | WK_3 | WK_0

        TWINE-128 (``N = 32``) additionally computes ``WK_23 ^= S(WK_30)``.
        ``CON_H`` and ``CON_L`` are the upper and lower 3 bits of the 6-bit
        round constant ``con``.
        """
        N = key_size // 4
        step = WordSBoxCipher(4, N, N, name=f"KS-step-{r}")
        sbox = SBox_CVL(SBox(_SBOX_TABLE), name="S")

        state = [(step.IN, i) for i in range(N)]
        for src, dst in _SBOX_PAIRS[key_size]:
            node_s = step.add_subcipher(sbox, [(step.IN, (src, 0))])
            node_x = step.add_subcipher(
                XOR_CVL(4, name=f"XOR_WK{dst}"),
                [(step.IN, (dst, 0)), (node_s, (0, 1))],
            )
            state[dst] = (node_x, 0)

        # Round constant: CON_H into WK_7, CON_L into WK_19.
        const = ((con >> 3) & 0x7) << (4 * (N - 1 - 7))
        const |= (con & 0x7) << (4 * (N - 1 - 19))
        node_c = step.add_subcipher(
            ConstXOR_CVL(key_size, const, name=f"CON{r}"),
            [(src, (w, i)) for i, (src, w) in enumerate(state)],
        )

        # Nibble rotation: input nibble i goes to output nibble perm[i].
        perm = [N - 1, N - 4, N - 3, N - 2, *list(range(N - 4))]
        node_p = step.add_subcipher(
            PermuteLayer_CVL(perm, word_coarseness=4, name="ROT"),
            [(node_c, (i, i)) for i in range(N)],
        )
        step.add_output([(node_p, (i, i)) for i in range(N)])
        return step


class TWINE_CVL(CipherImplementation_CVL, WordSBoxCipher):
    def __init__(self, R=36, key_schedule=None, key=None, name="TWINE"):
        r"""
        The CiVerLy implementation of TWINE.

        TWINE is a 64-bit block cipher with 80-bit or 128-bit key support.
        It uses a Type-2 GFS structure with 16 4-bit words, 4-bit S-boxes,
        and a word permutation. The round function consists of:

        - Round-key XOR on even-indexed words,
        - S-box application,
        - XOR with the adjacent odd-indexed word,
        - A word permutation (omitted in the last round).

        INPUT:

            - ``R`` -- integer (default: ``36``); Number of rounds.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass
              ``TWINE_KeySchedule_CVL(R=R)`` to use the real TWINE-80 key
              schedule (or ``TWINE_KeySchedule_CVL(R=R, key_size=128)`` for
              TWINE-128), or :class:`civerly.keyschedule.DefaultKeySchedule_CVL`
              to pass explicit round keys. Every 32-bit round key is applied as
              8 nibbles, so explicit round keys are given as ``8 * R`` nibbles
              (``DefaultKeySchedule_CVL(4, 8 * R)``), round by round, most
              significant nibble first. Defaults to ``None`` (no key schedule,
              all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The master
              key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round-key nibbles.

            - ``name`` -- string (default: ``"TWINE"``); Name of the cipher.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Encrypt with a 80-bit master key (test vector from the TWINE
        specification,
        https://www.nec.com/en/global/rd/tg/code/symenc/pdf/twine_LC11.pdf,
        App. B)::

            sage: from civerly.cipher_implementations.twine \
            ....:   import TWINE_CVL, TWINE_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = TWINE_CVL(
            ....:   key_schedule=TWINE_KeySchedule_CVL(),
            ....:   key=0x00112233445566778899, name="TWINE-80")
            sage: pt = int_to_vec(0x0123456789ABCDEF, 64)
            sage: hex(vec_to_int(cipher(pt)))
            '0x7c1f0f80b1df9c28'

        Encrypt with a 128-bit master key::

            sage: from civerly.cipher_implementations.twine \
            ....:   import TWINE_CVL, TWINE_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = TWINE_CVL(
            ....:   key_schedule=TWINE_KeySchedule_CVL(key_size=128),
            ....:   key=0x00112233445566778899AABBCCDDEEFF, name="TWINE-128")
            sage: pt = int_to_vec(0x0123456789ABCDEF, 64)
            sage: hex(vec_to_int(cipher(pt)))
            '0x979ff9b379b5a9b8'

        Encrypt with explicit round keys, passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.cipher_implementations.twine \
            ....:   import TWINE_CVL, TWINE_KeySchedule_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = TWINE_KeySchedule_CVL()(0x00112233445566778899)
            sage: cipher = TWINE_CVL(
            ....:   key_schedule=DefaultKeySchedule_CVL(4, 8 * 36), key=rks,
            ....:   name="TWINE-explicit")
            sage: pt = int_to_vec(0x0123456789ABCDEF, 64)
            sage: hex(vec_to_int(cipher(pt)))
            '0x7c1f0f80b1df9c28'

        Model the cipher with MILP, reproducing
        https://www.nec.com/en/global/rd/tg/code/symenc/pdf/twine_LC11.pdf,
        Table 5 (4 rounds has 3 active SBoxes, each with optimal prob 2^{-2})::

            sage: # optional - scip espresso
            sage: from civerly.cipher_implementations.twine import TWINE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: cipher = TWINE_CVL(R=4, name="TWINE-4")
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            Using existing file ..., make sure it is up to date!
            3296 variables and 5729 constraints were written to ...
            6

        Model the cipher with SAT::

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.twine import TWINE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = TWINE_CVL(R=3, name="TWINE-3")
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(0, 30),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            Using existing file ..., make sure it is up to date!
            2536 variables and 6553 clauses were written to ...
            4

        Linear cryptanalysis with MILP::

            sage: from civerly.cipher_implementations.twine import TWINE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: cipher = TWINE_CVL(R=4, name="TWINE-4-lin")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            Using existing file ..., make sure it is up to date!
            3296 variables and 5793 constraints were written to ...
            3
        """
        super().__init__(4, 16, 16, R=R, key_schedule=key_schedule, key=key, name=name)

        sbox = SBox_CVL(SBox(_SBOX_TABLE), name="S")

        # ------------------------------------------------------------------
        # Round template with permutation (used for rounds 1 to R-1)
        # ------------------------------------------------------------------
        twine_round = WordSBoxCipher(4, 16, 16, name="round")

        # Round-key XOR on even-indexed words
        rk_nodes = []
        for j in range(8):
            rk = RoundkeyXOR_CVL(4, const=0, name=f"rk{j}")
            node_rk = twine_round.add_subcipher(rk, [(twine_round.IN, (2 * j, 0))])
            rk_nodes.append(node_rk)

        # S-box layer on the XOR results
        sbox_nodes = []
        for j in range(8):
            node_s = twine_round.add_subcipher(sbox, [(rk_nodes[j], (0, 0))])
            sbox_nodes.append(node_s)

        # XOR with odd-indexed words
        xor_nodes = []
        for j in range(8):
            xor = XOR_CVL(4, name=f"xor{j}")
            node_xor = twine_round.add_subcipher(
                xor,
                [
                    (sbox_nodes[j], (0, 0)),
                    (twine_round.IN, (2 * j + 1, 1)),
                ],
            )
            xor_nodes.append(node_xor)

        # Permutation layer
        perm = PermuteLayer_CVL(_PERMUTATION, word_coarseness=4, name="perm")

        perm_edges = []
        for j in range(8):
            perm_edges.append((twine_round.IN, (2 * j, 2 * j)))
            perm_edges.append((xor_nodes[j], (0, 2 * j + 1)))

        node_perm = twine_round.add_subcipher(perm, perm_edges)
        twine_round.add_output([(node_perm, (i, i)) for i in range(16)])

        # ------------------------------------------------------------------
        # Final round template without permutation (used for round R)
        # ------------------------------------------------------------------
        twine_final = WordSBoxCipher(4, 16, 16, name="final")

        rk_nodes_final = []
        for j in range(8):
            rk = RoundkeyXOR_CVL(4, const=0, name=f"rk_final{j}")
            node_rk = twine_final.add_subcipher(rk, [(twine_final.IN, (2 * j, 0))])
            rk_nodes_final.append(node_rk)

        sbox_nodes_final = []
        for j in range(8):
            node_s = twine_final.add_subcipher(sbox, [(rk_nodes_final[j], (0, 0))])
            sbox_nodes_final.append(node_s)

        xor_nodes_final = []
        for j in range(8):
            xor = XOR_CVL(4, name=f"xor_final{j}")
            node_xor = twine_final.add_subcipher(
                xor,
                [
                    (sbox_nodes_final[j], (0, 0)),
                    (twine_final.IN, (2 * j + 1, 1)),
                ],
            )
            xor_nodes_final.append(node_xor)

        final_output_edges = []
        for j in range(8):
            final_output_edges.append((twine_final.IN, (2 * j, 2 * j)))
            final_output_edges.append((xor_nodes_final[j], (0, 2 * j + 1)))
        twine_final.add_output(final_output_edges)

        # ------------------------------------------------------------------
        # Build the full cipher
        # ------------------------------------------------------------------
        node = self.IN
        for _ in range(self.R - 1):
            node = self.add_subcipher(twine_round, [(node, (i, i)) for i in range(16)])

        # Final round (round R)
        node = self.add_subcipher(twine_final, [(node, (i, i)) for i in range(16)])

        self.add_output([(node, (i, i)) for i in range(16)])

        # Round-key nibbles as they live inside ``self`` (after deep-copying),
        # round by round, most significant nibble first.
        self._rk_components = [
            self.nodes[r + 1].nodes[rk_nodes[j]]
            for r in range(self.R - 1)
            for j in range(8)
        ] + [self.nodes[self.R].nodes[rk_nodes_final[j]] for j in range(8)]

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
