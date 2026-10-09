from sage.crypto.sbox import SBox

from civerly.component import XOR_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.wordsboxcipher import WordSBoxCipher


class TWINE_CVL:
    _SBOX_TABLE = (
        0xC,
        0x0,
        0xF,
        0xA,
        0x2,
        0xB,
        0x9,
        0x5,
        0x8,
        0x3,
        0xD,
        0x7,
        0x1,
        0xE,
        0x6,
        0x4,
    )
    _PERMUTATION = (
        5,
        0,
        1,
        4,
        7,
        12,
        3,
        8,
        13,
        6,
        9,
        2,
        15,
        10,
        11,
        14,
    )
    _ROUND_CONSTANTS = (
        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x03,
        0x06,
        0x0C,
        0x18,
        0x30,
        0x23,
        0x05,
        0x0A,
        0x14,
        0x28,
        0x13,
        0x26,
        0x0F,
        0x1E,
        0x3C,
        0x3B,
        0x35,
        0x29,
        0x11,
        0x22,
        0x07,
        0x0E,
        0x1C,
        0x38,
        0x33,
        0x25,
        0x09,
        0x12,
        0x24,
    )

    @staticmethod
    def _key_schedule_80(key):
        r"""
        Compute the 36 round keys for TWINE-80.

        INPUT:

            - ``key`` -- integer; The 80-bit master key.

        OUTPUT: A list of 36 32-bit round keys.
        """
        WK = [(key >> (4 * (19 - i))) & 0xF for i in range(20)]
        rks = []
        for r in range(1, 36):
            rk = (
                (WK[1] << 28)
                | (WK[3] << 24)
                | (WK[4] << 20)
                | (WK[6] << 16)
                | (WK[13] << 12)
                | (WK[14] << 8)
                | (WK[15] << 4)
                | WK[16]
            )
            rks.append(rk)
            WK[1] = WK[1] ^ TWINE_CVL._SBOX_TABLE[WK[0]]
            WK[4] = WK[4] ^ TWINE_CVL._SBOX_TABLE[WK[16]]
            con = TWINE_CVL._ROUND_CONSTANTS[r - 1]
            WK[7] = WK[7] ^ ((con >> 3) & 0x7)
            WK[19] = WK[19] ^ (con & 0x7)
            WK[0:4] = [*WK[1:4], WK[0]]
            WK[0:20] = WK[4:20] + WK[0:4]
        rk = (
            (WK[1] << 28)
            | (WK[3] << 24)
            | (WK[4] << 20)
            | (WK[6] << 16)
            | (WK[13] << 12)
            | (WK[14] << 8)
            | (WK[15] << 4)
            | WK[16]
        )
        rks.append(rk)
        return rks

    @staticmethod
    def _key_schedule_128(key):
        r"""
        Compute the 36 round keys for TWINE-128.

        INPUT:

            - ``key`` -- integer; The 128-bit master key.

        OUTPUT: A list of 36 32-bit round keys.
        """
        WK = [(key >> (4 * (31 - i))) & 0xF for i in range(32)]
        rks = []
        for r in range(1, 36):
            rk = (
                (WK[2] << 28)
                | (WK[3] << 24)
                | (WK[12] << 20)
                | (WK[15] << 16)
                | (WK[17] << 12)
                | (WK[18] << 8)
                | (WK[28] << 4)
                | WK[31]
            )
            rks.append(rk)
            WK[1] = WK[1] ^ TWINE_CVL._SBOX_TABLE[WK[0]]
            WK[4] = WK[4] ^ TWINE_CVL._SBOX_TABLE[WK[16]]
            WK[23] = WK[23] ^ TWINE_CVL._SBOX_TABLE[WK[30]]
            con = TWINE_CVL._ROUND_CONSTANTS[r - 1]
            WK[7] = WK[7] ^ ((con >> 3) & 0x7)
            WK[19] = WK[19] ^ (con & 0x7)
            WK[0:4] = [*WK[1:4], WK[0]]
            WK[0:32] = WK[4:32] + WK[0:4]
        rk = (
            (WK[2] << 28)
            | (WK[3] << 24)
            | (WK[12] << 20)
            | (WK[15] << 16)
            | (WK[17] << 12)
            | (WK[18] << 8)
            | (WK[28] << 4)
            | WK[31]
        )
        rks.append(rk)
        return rks

    def __init__(self, R=36, rks=None, key=None, key_size=80, name=None):
        r"""
        The CiVerLy implementation of TWINE.

        TWINE is a 64-bit block cipher with 80-bit or 128-bit key support.
        It uses a Type-2 GFS structure with 16 4-bit words, 4-bit S-boxes,
        and a word permutation. The round function consists of:

        - Round-key XOR on even-indexed words,
        - S-box application,
        - XOR with the adjacent odd-indexed word,
        - A word permutation (omitted in the last round).

        It takes the following arguments:

            - ``R`` -- integer (default: ``36``); Number of rounds.

            - ``rks`` -- list (optional); Explicit round keys. Each round key
              is a 32-bit integer containing 8 nibbles. If provided,
              ``key`` is ignored.

            - ``key`` -- integer (optional); Master key for key-schedule
              derivation.

            - ``key_size`` -- integer (default: ``80``); Key size in bits,
              either ``80`` or ``128``.

            - ``name`` -- string (optional); Name of the cipher.

        EXAMPLES:

        Encrypt with a 80-bit master key (test vector from the TWINE
        specification, https://www.nec.com/en/global/rd/tg/code/symenc/pdf/twine_LC11.pdf,
        App. B)::

            sage: from civerly.cipher_implementations.twine import TWINE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = TWINE_CVL(
            ....:   key=0x00112233445566778899, key_size=80, name="TWINE-80")
            sage: pt = int_to_vec(0x0123456789ABCDEF, 64)
            sage: hex(vec_to_int(cipher(pt)))
            '0x7c1f0f80b1df9c28'

        Encrypt with a 128-bit master key::

            sage: from civerly.cipher_implementations.twine import TWINE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = TWINE_CVL(
            ....:   key=0x00112233445566778899AABBCCDDEEFF,
            ....:   key_size=128, name="TWINE-128")
            sage: pt = int_to_vec(0x0123456789ABCDEF, 64)
            sage: hex(vec_to_int(cipher(pt)))
            '0x979ff9b379b5a9b8'

        Encrypt with explicit round keys::

            sage: from civerly.cipher_implementations.twine import TWINE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = TWINE_CVL._key_schedule_80(0x00112233445566778899)
            sage: cipher = TWINE_CVL(rks=rks, name="TWINE-explicit")
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
        if name is None:
            name = "TWINE"

        if rks is None and key is not None:
            if key_size == 80:
                rks = TWINE_CVL._key_schedule_80(key)
            elif key_size == 128:
                rks = TWINE_CVL._key_schedule_128(key)
            else:
                raise ValueError(f"key_size must be 80 or 128, got {key_size}")

        if rks is None:
            rks = [0 for _ in range(R)]

        if len(rks) < R:
            raise ValueError(f"Need {R} round keys, got {len(rks)}")

        rks = rks[:R]

        sbox = SBox_CVL(SBox(TWINE_CVL._SBOX_TABLE), name="S")

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
        perm = PermuteLayer_CVL(
            TWINE_CVL._PERMUTATION,
            word_coarseness=4,
            name="perm",
        )

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
        cipher = WordSBoxCipher(4, 16, 16, name=name)
        node = cipher.IN

        for r in range(R - 1):
            for j in range(8):
                rk_val = (rks[r] >> (28 - 4 * j)) & 0xF
                twine_round.nodes[rk_nodes[j]].const = rk_val
            node = cipher.add_subcipher(
                twine_round, [(node, (i, i)) for i in range(16)]
            )

        # Final round (round R)
        for j in range(8):
            rk_val = (rks[R - 1] >> (28 - 4 * j)) & 0xF
            twine_final.nodes[rk_nodes_final[j]].const = rk_val
        node = cipher.add_subcipher(twine_final, [(node, (i, i)) for i in range(16)])

        cipher.add_output([(node, (i, i)) for i in range(16)])
        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
