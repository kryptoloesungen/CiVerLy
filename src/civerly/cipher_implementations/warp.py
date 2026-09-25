from sage.crypto.sbox import SBox

from civerly.component import XOR_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.wordsboxcipher import WordSBoxCipher


class WARP_CVL:
    def __init__(self, R=41, key=None, rks=None, name=None):
        r"""
        The CiVerLy implementation of WARP. It takes in the following
        arguments:

            - ``R`` -- integer (default: ``41``); Number of rounds.

            - ``key`` -- integer (optional); A 128-bit master key. The
              lower 64 bits are ``K1`` and the upper 64 bits are ``K0``.

            - ``rks`` -- list (optional); Explicit round keys for each
              of the ``R`` rounds. If given, overrides ``key``. Each
              element should be a 64-bit integer representing 16 nibbles.

            - ``name`` -- string (optional); The name of the cipher.

        EXAMPLES:

        Encrypt using the test vectors from the specification::

            sage: from civerly.cipher_implementations.warp import WARP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: # Test vector 1
            sage: key = 0x0123456789abcdeffedcba9876543210
            sage: pt  = 0x0123456789abcdeffedcba9876543210
            sage: ct  = 0x24ce0a8efd9f32de529d5fdf45703a8d
            sage: warp = WARP_CVL(key=key)
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
            sage: warp3 = WARP_CVL(key=key3)
            sage: vec_to_int(warp3(int_to_vec(pt3, 128))) == ct3
            True

        Model the cipher with MILP (bitwise)::

            sage: # optional - scip espresso
            sage: from civerly.cipher_implementations.warp import WARP_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: warp = WARP_CVL(R=4, key=0x0)
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
            ....:   warp = WARP_CVL(R=8, key=0x0)
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
        if name is None:
            name = "WARP"

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

        # Derive round keys
        if rks is not None:
            round_keys = rks
        elif key is not None:
            k0 = (key >> 64) & ((1 << 64) - 1)
            k1 = key & ((1 << 64) - 1)
            round_keys = [k0 if r % 2 == 0 else k1 for r in range(40)] + [k0]
        else:
            round_keys = [0 for _ in range(41)]

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
        warp_cipher = WordSBoxCipher(4, 32, 32, name=name)

        cipher_node = warp_cipher.IN
        for r in range(min(R, 40)):
            warp_round.nodes[node_key].const = round_keys[r]
            warp_round.nodes[node_rc].const = rc_consts[r]
            cipher_node = warp_cipher.add_subcipher(
                warp_round, [(cipher_node, (i, i)) for i in range(32)]
            )

        # Final round (always uses K^0 and RC^{41})
        if R >= 41:
            warp_final.nodes[node_key_f].const = round_keys[40]
            warp_final.nodes[node_rc_f].const = rc_consts[40]
            cipher_node = warp_cipher.add_subcipher(
                warp_final, [(cipher_node, (i, i)) for i in range(32)]
            )

        warp_cipher.add_output([(cipher_node, (i, i)) for i in range(32)])

        self.warp_cipher = warp_cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.warp_cipher
