from sage.crypto.sbox import SBox

from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import XOR_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.keyschedule import KeySchedule
from civerly.wordsboxcipher import WordSBoxCipher


class WARP_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=41):
        r"""
        WARP key schedule as a CiVerLy DAG.

        The 128-bit master key is split into two halves ``K0`` (upper 64 bits)
        and ``K1`` (lower 64 bits), which are used alternately as round keys,
        starting with ``K0``. No computation is needed: each 64-bit round key
        is wired directly from the corresponding half of the input.

        INPUT:

            - ``R`` -- integer (default: ``41``); Number of rounds, with the
              same meaning as in :class:`WARP_CVL`. One 64-bit round key is
              produced per round, for at most 41 rounds.

        EXAMPLES::

            sage: from civerly.cipher_implementations.warp import (
            ....:   WARP_KeySchedule_CVL)
            sage: ks = WARP_KeySchedule_CVL()
            sage: rks = ks(0x0123456789abcdeffedcba9876543210)
            sage: len(rks)
            41
            sage: [hex(k) for k in rks[:2]]
            ['0x123456789abcdef', '0xfedcba9876543210']
            sage: rks[40] == rks[0]
            True
            sage: ks.input_length, ks.output_length
            (128, 2624)

        TESTS:

        The number of round keys matches the round-key components of
        :class:`WARP_CVL`::

            sage: from civerly.cipher_implementations.warp import WARP_CVL
            sage: all(
            ....:   len(WARP_KeySchedule_CVL(R=r)(0))
            ....:   == len(WARP_CVL(R=r)._rk_components)
            ....:   for r in [1, 2, 5, 40, 41])
            True
        """
        n_rk = min(R, 41)
        super().__init__(128, 64 * n_rk, name="WARP-KeySchedule")
        self.R = R
        self.add_output(
            [
                (self.IN, (64 * (r % 2) + i, 64 * r + i))
                for r in range(n_rk)
                for i in range(64)
            ]
        )

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into the list of 64-bit round keys.

        INPUT:

            - ``master_key`` -- integer; the 128-bit master key.

        OUTPUT: List of ``min(R, 41)`` 64-bit round-key integers.
        """
        from civerly.cipher import Cipher
        from civerly.util import int_to_vec, vec_to_int

        bits = Cipher.eval(self, int_to_vec(master_key, self.input_length))
        return [
            vec_to_int(bits[64 * i : 64 * (i + 1)])
            for i in range(self.output_length // 64)
        ]


class WARP_CVL(CipherImplementation_CVL, WordSBoxCipher):
    def __init__(self, R=41, key_schedule=None, key=None, name="WARP"):
        r"""
        The CiVerLy implementation of WARP.

        INPUT:

            - ``R`` -- integer (default: ``41``); Number of rounds. The first
              ``min(R, 40)`` rounds include the nibble shuffle; the 41st
              round (only present if ``R >= 41``) omits it. At most 41
              rounds are built.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass :class:`WARP_KeySchedule_CVL` (with the
              same ``R``) to use the real WARP key schedule, or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (one per round, 64 bits each). Defaults to
              ``None`` (no key schedule, all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The 128-bit
              master key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. The lower
              64 bits are ``K1`` and the upper 64 bits are ``K0``. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first).

            - ``name`` -- string (default: ``"WARP"``); The name of the cipher.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Encrypt using the test vectors from the specification::

            sage: from civerly.cipher_implementations.warp \
            ....:   import WARP_CVL, WARP_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: # Test vector 1
            sage: key = 0x0123456789abcdeffedcba9876543210
            sage: pt  = 0x0123456789abcdeffedcba9876543210
            sage: ct  = 0x24ce0a8efd9f32de529d5fdf45703a8d
            sage: warp = WARP_CVL(key_schedule=WARP_KeySchedule_CVL(), key=key)
            sage: vec_to_int(warp(int_to_vec(pt, 128))) == ct
            True
            sage: # Test vector 2
            sage: pt2 = 0x00112233445566778899aabbccddeeff
            sage: ct2 = 0x923c64f92827ee62b9667dd2548fb12c
            sage: vec_to_int(warp(int_to_vec(pt2, 128))) == ct2
            True
            sage: # Test vector 3
            sage: key3 = 0x0acd022f680a547fee03c0867b09e3d7
            sage: pt3  = 0xaf6cdd90fc5a6eaa897bcd1208d391e1
            sage: ct3  = 0x6123995f1924d31425641acdd058dd46
            sage: warp3 = WARP_CVL(key_schedule=WARP_KeySchedule_CVL(), key=key3)
            sage: vec_to_int(warp3(int_to_vec(pt3, 128))) == ct3
            True
            sage: warp3.set_round_keys(key)
            sage: vec_to_int(warp3(int_to_vec(pt, 128))) == ct
            True

        Explicit round keys can be passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: rks = WARP_KeySchedule_CVL()(key3)
            sage: warp = WARP_CVL(
            ....:   key_schedule=DefaultKeySchedule_CVL(64, 41), key=rks)
            sage: vec_to_int(warp(int_to_vec(pt3, 128))) == ct3
            True

        Model the cipher with MILP (bitwise)::

            sage: # optional - scip espresso
            sage: from civerly.cipher_implementations.warp import WARP_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: warp = WARP_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   warp.analyse(model_options)
            9408 variables and 13249 constraints were written to ...
            6

        Model the cipher with SAT::

            sage: from civerly.cipher_implementations.warp import WARP_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   warp = WARP_CVL(R=8)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   warp.analyse(model_options)
            ....:   trail = str(warp.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            18048 variables and 42369 clauses were written to ...
            22
        """
        super().__init__(4, 32, 32, R=R, key_schedule=key_schedule, key=key, name=name)

        # 4-bit S-box
        sbox = SBox(
            [
                0xC,
                0xA,
                0xD,
                0x3,
                0xE,
                0xB,
                0xF,
                0x7,
                0x8,
                0x9,
                0x1,
                0x5,
                0x0,
                0x2,
                0x4,
                0x6,
            ]
        )
        s = SBox_CVL(sbox, name="S")

        # Round constants RC0 and RC1 for rounds 1..41 (0-indexed 0..40)
        RC0 = [
            0x0,
            0x0,
            0x1,
            0x3,
            0x7,
            0xF,
            0xF,
            0xF,
            0xE,
            0xD,
            0xA,
            0x5,
            0xA,
            0x5,
            0xB,
            0x6,
            0xC,
            0x9,
            0x3,
            0x6,
            0xD,
            0xB,
            0x7,
            0xE,
            0xD,
            0xB,
            0x6,
            0xD,
            0xA,
            0x4,
            0x9,
            0x2,
            0x4,
            0x9,
            0x3,
            0x7,
            0xE,
            0xC,
            0x8,
            0x1,
            0x2,
        ]
        RC1 = [
            0x4,
            0xC,
            0xC,
            0xC,
            0xC,
            0xC,
            0x8,
            0x4,
            0x8,
            0x4,
            0x8,
            0x4,
            0xC,
            0x8,
            0x0,
            0x4,
            0xC,
            0x8,
            0x4,
            0xC,
            0xC,
            0x8,
            0x4,
            0xC,
            0x8,
            0x4,
            0x8,
            0x0,
            0x4,
            0x8,
            0x0,
            0x4,
            0xC,
            0xC,
            0x8,
            0x0,
            0x0,
            0x4,
            0x8,
            0x4,
            0xC,
        ]

        # Precompute 128-bit round-constant values for RoundkeyXOR_CVL.
        # Word 1 gets RC0, word 3 gets RC1.
        rc_consts = [(RC0[r] << 120) | (RC1[r] << 112) for r in range(41)]

        # S-box layer on 16 nibbles
        sbox_layer = WordSBoxCipher(4, 16, 16, name="SBoxLayer")
        for j in range(16):
            node = sbox_layer.add_subcipher(s, [(sbox_layer.IN, (j, 0))])
            sbox_layer.add_output([(node, (0, j))])

        # Key addition on 16 nibbles
        key_add = RoundkeyXOR_CVL(64, 0x0, name="KeyAdd")

        # XOR for Feistel step: xor(S(even)+key, odd)
        feistel_xor = XOR_CVL(64, name="FeistelXOR")

        # Round-constant addition on full 32-nibble state
        rc_add = RoundkeyXOR_CVL(128, 0x0, name="RCAdd")

        # Shuffle permutation on 32 nibbles (wordwise)
        shuffle = PermuteLayer_CVL(
            [
                31,
                6,
                29,
                14,
                1,
                12,
                21,
                8,
                27,
                2,
                3,
                0,
                25,
                4,
                23,
                10,
                15,
                22,
                13,
                30,
                17,
                28,
                5,
                24,
                11,
                18,
                19,
                16,
                9,
                20,
                7,
                26,
            ],
            word_coarseness=4,
            name="Shuffle",
        )

        # Build the round subcipher (rounds 1..40, with shuffle)
        # --------------------------------------------------------
        warp_round = WordSBoxCipher(4, 32, 32, name="warp_round")

        # S-box on even input words
        node_sbox = warp_round.add_subcipher(
            sbox_layer, [(warp_round.IN, (2 * i, i)) for i in range(16)]
        )

        # Add round key to S-box outputs
        node_key = warp_round.add_subcipher(
            key_add, [(node_sbox, (i, i)) for i in range(16)]
        )

        # XOR with odd input words
        node_xor = warp_round.add_subcipher(
            feistel_xor,
            [(node_key, (i, i)) for i in range(16)]
            + [(warp_round.IN, (2 * i + 1, i + 16)) for i in range(16)],
        )

        # Combine even words (unchanged) and updated odd words,
        # then add round constants
        node_rc = warp_round.add_subcipher(
            rc_add,
            [(warp_round.IN, (2 * i, 2 * i)) for i in range(16)]
            + [(node_xor, (i, 2 * i + 1)) for i in range(16)],
        )

        # Apply shuffle to the full state
        node_shuffle = warp_round.add_subcipher(
            shuffle, [(node_rc, (i, i)) for i in range(32)]
        )

        warp_round.add_output([(node_shuffle, (i, i)) for i in range(32)])
        # --------------------------------------------------------

        # Build the final round subcipher (round 41, no shuffle)
        # --------------------------------------------------------
        warp_final = WordSBoxCipher(4, 32, 32, name="warp_final")

        node_sbox_f = warp_final.add_subcipher(
            sbox_layer, [(warp_final.IN, (2 * i, i)) for i in range(16)]
        )

        node_key_f = warp_final.add_subcipher(
            key_add, [(node_sbox_f, (i, i)) for i in range(16)]
        )

        node_xor_f = warp_final.add_subcipher(
            feistel_xor,
            [(node_key_f, (i, i)) for i in range(16)]
            + [(warp_final.IN, (2 * i + 1, i + 16)) for i in range(16)],
        )

        node_rc_f = warp_final.add_subcipher(
            rc_add,
            [(warp_final.IN, (2 * i, 2 * i)) for i in range(16)]
            + [(node_xor_f, (i, 2 * i + 1)) for i in range(16)],
        )

        warp_final.add_output([(node_rc_f, (i, i)) for i in range(32)])
        # --------------------------------------------------------

        # Assemble the cipher
        cipher_node = self.IN
        rk_components = []
        for r in range(min(self.R, 40)):
            warp_round.nodes[node_rc].const = rc_consts[r]
            cipher_node = self.add_subcipher(
                warp_round, [(cipher_node, (i, i)) for i in range(32)]
            )
            rk_components.append(self.nodes[r + 1].nodes[node_key])

        # Final round (uses RC^{41}, no shuffle)
        if self.R >= 41:
            warp_final.nodes[node_rc_f].const = rc_consts[40]
            cipher_node = self.add_subcipher(
                warp_final, [(cipher_node, (i, i)) for i in range(32)]
            )
            rk_components.append(self.nodes[41].nodes[node_key_f])

        self.add_output([(cipher_node, (i, i)) for i in range(32)])

        self._rk_components = rk_components

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
