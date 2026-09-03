from sage.crypto.sbox import SBox as SBox_sage

from civerly.component import PermuteLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.wordsboxcipher import WordSBoxCipher


class RECTANGLE_CVL:
    def __init__(self, R=25, key_schedule=None, k=None, name="RECTANGLE"):
        r"""
        CiVerly implementation of the Rectangle cipher (https://eprint.iacr.org/2014/084.pdf).
        It takes the following parameters:

            - ``R`` -- integer; Number of rounds (default: 25)

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``k`` via ``set_round_keys``. Pass
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (see ``k``). Defaults to ``None`` (no key
              schedule, all-zero round keys).

            - ``k`` -- integer (optional); The master key passed to
              ``key_schedule``, immediately expanded and injected via
              ``set_round_keys`` when both are given. Has no effect when
              ``key_schedule`` is ``None``.

            - ``name`` -- string; The name of the cipher (default: "RECTANGLE").
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).

        EXAMPLES::

            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rectangle_cipher = RECTANGLE_CVL(R=10)
            sage: hex(vec_to_int(rectangle_cipher(int_to_vec(0xabcd1234, 64))))
            '0xf0e862f7d288180d'

        TESTS::
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: k = 0xe000f00000000000c0001000ff0000309000df00ccf000c0df006cf099cf3f311cf099cfddac3d1fd9cf8dac221af642adac821aa5104f6b521a3510e34e8935d510634edb762078134e9b76d2dc4bdfeb76a2dc5c18a4cde2dcec18eeb91f282c180eb9f43424e6feb92434268eb8fc2434468e0f40180da68eef4051124b972f404112a2ed18dab11262ed7f23cb3af2ed5f233865a8d63f2328657f5c793bb8659f5c5ecff3ed9f5c8ecfc43ae26e3ecf143a6f7820ad343aaf78301ab9ab8f78501a136fc
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rectangle_cipher = RECTANGLE_CVL(R=25, k=k, key_schedule=DefaultKeySchedule_CVL(64, 26))
            sage: vec_to_int(rectangle_cipher(int_to_vec(0x0, 64))) == 0x2D96E354E8B10874
            True

            sage: k = 0xffffffffffffffff0f01fff0fff0f000fef3fffff000f0f00f09f00cf0fff00ef00ff0f5f003c1f0f914f00ac1f7731fecf0c1f67315a7383c1b7316a73a536f6f34a738536869cb9050536c69c30a8000e969cc0a8caf9f8bd90a84af92baaadb0caf95baa66b48a944baa16b45dd65fe186b4fdd6496d07facdd6796db1029770d96db102c3f1698b810243f1dac5baea73f1cac5bcdcb9cbaac5bcdc7e46219c1cdc1e46820e500d2e46320e5cebb3a7320e3cebab5265ccaceb0b5255b8c0de2b5225b847fc4553b5b897fc63b3f
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rectangle_cipher = RECTANGLE_CVL(R=25, k=k, key_schedule=DefaultKeySchedule_CVL(64, 26))
            sage: vec_to_int(rectangle_cipher(int_to_vec(0xFFFFFFFFFFFFFFFF, 64))) == 0x9945AA34AE3D0112
            True

            sage: # optional - scip
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            1932 variables and 2133 constraints were written to ...
            4

            sage: # optional - scip
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            7872 variables and 8641 constraints were written to ...
            10

            sage: # optional - gurobi # optional - espresso
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            4192 variables and 4545 constraints were written to ...
            4

        Model the cipher with SAT:

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            ....:   trail = str(rectangle_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            7872 variables and 17473 clauses were written to ...
            10

        Linear cryptanalysis::

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            ....:   trail = str(rectangle_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            7872 variables and 17217 clauses were written to ...
            6

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            7872 variables and 17217 clauses were written to ...
            6

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=5)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            9712 variables and 21297 clauses were written to ...
            8
            sage: trail = str(rectangle_cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.rectangle \
            ....:   import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=5)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   rectangle_cipher.analyse(model_options)
            9712 variables and 21617 clauses were written to ...
            14

            """

        # RECTANGLE necessites R+1 round keys, which default to zeros
        rks = [0] * (R + 1)

        # RECTANGLE S-box specifications
        RECTANGLE_SBOX = (
            0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2,
        )  # fmt: skip

        # SubColumn
        # 16 parallel 4-bit S-boxes
        sb = SBox_CVL(SBox_sage(RECTANGLE_SBOX), name="SBox")
        sboxlayer = WordSBoxCipher(4, 16, 16, name="SubColumn_SBoxLayer")
        for j in range(16):
            n = sboxlayer.add_subcipher(sb, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(n, (0, j))])

        # the state matrix is a matrix of 4 rows, each 16 bits
        # since the state is bitwise, then we have to transform it into nibbles
        # CiVerLy assumes that each row of the internal state is a word/nibble
        # this function converts 4 rows with 16 columns into 16 nibbles each 4-bits
        # each 4-bit nibble is constructed from one bit of each column
        # each column i is constructed as (row_0[i], row_1[i], row_2[i], row_3[i])
        def bit_to_nibble():
            perm = [0] * 64
            for row in range(4):
                for b in range(16):
                    src_lsb = (3 - row) * 16 + b
                    dest_lsb = 4 * b + row
                    src_msb = 63 - src_lsb
                    dest_msb = 63 - dest_lsb
                    perm[src_msb] = dest_msb
            return perm

        tr = bit_to_nibble()
        transpose = PermuteLayer_CVL(
            tr, word_coarseness=1, name="Transpose_bitslice_to_nibbles"
        )

        # this function computes the inverse of the permutation
        def invert_perm(p):
            inv = [0] * len(p)
            for src, dst in enumerate(p):
                inv[dst] = src
            return inv

        tr_inv = invert_perm(tr)
        transpose_inv = PermuteLayer_CVL(
            tr_inv, word_coarseness=1, name="Transpose_nibbles_to_bitslice"
        )
        # SubColumn as: T^{-1} . S . T
        # Transpose from bitslice layout to nibble layout
        # S applies the Sbox
        # Restore back to bitslice
        subcolumn = WordSBoxCipher(4, 16, 16, name="SubColumn")
        x = subcolumn.IN
        x = subcolumn.add_subcipher(transpose, [(x, (i, i)) for i in range(16)])
        x = subcolumn.add_subcipher(sboxlayer, [(x, (i, i)) for i in range(16)])
        x = subcolumn.add_subcipher(transpose_inv, [(x, (i, i)) for i in range(16)])
        subcolumn.add_output([(x, (i, i)) for i in range(16)])

        # ShiftRows left shifts each row by a certain amount:
        # row0: rotl 0
        # row1: rotl 1
        # row2: rotl 12
        # row3: rotl 13
        # we convert the bit positions from LSB to MSB indexing to match the paper's specifications
        def shiftrows_perm_msb():
            shifts = [0, 1, 12, 13]
            perm = [0] * 64
            for row in range(4):
                s = shifts[row]
                base = (3 - row) * 16
                for b in range(16):
                    src_lsb = base + b
                    dest_lsb = base + ((b + s) % 16)
                    src_msb = 63 - src_lsb
                    dest_msb = 63 - dest_lsb
                    perm[src_msb] = dest_msb
            return perm

        shiftrows = PermuteLayer_CVL(
            shiftrows_perm_msb(), word_coarseness=1, name="ShiftRows"
        )

        # AddRoundKey
        ark = RoundkeyXOR_CVL(64, 0x0, name="AddRoundKey")
        # One round of RECTANGLE
        rectangle_round = WordSBoxCipher(4, 16, 16, name="RECTANGLE_round")
        st = rectangle_round.IN
        n_ark = rectangle_round.add_subcipher(ark, [(st, (i, i)) for i in range(16)])
        st = rectangle_round.add_subcipher(
            subcolumn, [(n_ark, (i, i)) for i in range(16)]
        )
        st = rectangle_round.add_subcipher(shiftrows, [(st, (i, i)) for i in range(16)])
        rectangle_round.add_output([(st, (i, i)) for i in range(16)])

        # Full RECTANGLE cipher
        rectangle = WordSBoxCipher(4, 16, 16, name=name)
        st = rectangle.IN
        for r in range(R):
            rectangle_round.nodes[n_ark].const = rks[r]
            st = rectangle.add_subcipher(
                rectangle_round, [(st, (i, i)) for i in range(16)]
            )

        # final AddRoundKey with K[25]
        ark.const = rks[R]
        st = rectangle.add_subcipher(ark, [(st, (i, i)) for i in range(16)])

        rectangle.add_output([(st, (i, i)) for i in range(16)])
        rectangle._rk_components = [
            rectangle.nodes[r + 1].nodes[n_ark] for r in range(R)
        ] + [rectangle.nodes[R + 1]]
        rectangle.key_schedule = key_schedule
        if key_schedule is not None and k is not None:
            rectangle.set_round_keys(k)
        self.rectangle_cipher = rectangle

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.rectangle_cipher
