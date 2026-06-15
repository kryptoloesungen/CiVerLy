from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from sage.crypto.sbox import SBox as SBox_sage

class RECTANGLE_CVL:
    def __init__(self, R=25, rks=None, name=None): 
        r"""
        EXAMPLES::
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rectangle_cipher = RECTANGLE_CVL(R=10)
            sage: hex(vec_to_int(rectangle_cipher(int_to_vec(0xabcd1234, 64))))
            '0xf0e862f7d288180d'

        TESTS::
            sage: rks = [
            ....:   0x0000000000000000, 0x000e000f00000000, 
            ....:   0x000c0001000ff000, 0x0309000df00ccf00,
            ....:   0x0c0df006cf099cf3, 0xf311cf099cfddac3,
            ....:   0xd1fd9cf8dac221af, 0x642adac821aa5104,
            ....:   0xf6b521a3510e34e8, 0x935d510634edb762,
            ....:   0x078134e9b76d2dc4, 0xbdfeb76a2dc5c18a,
            ....:   0x4cde2dcec18eeb91, 0xf282c180eb9f4342,
            ....:   0x4e6feb92434268eb, 0x8fc2434468e0f401,
            ....:   0x80da68eef4051124, 0xb972f404112a2ed1,
            ....:   0x8dab11262ed7f23c, 0xb3af2ed5f233865a,
            ....:   0x8d63f2328657f5c7, 0x93bb8659f5c5ecff,
            ....:   0x3ed9f5c8ecfc43ae, 0x26e3ecf143a6f782,
            ....:   0x0ad343aaf78301ab, 0x9ab8f78501a136fc
            ....: ]
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rectangle_cipher = RECTANGLE_CVL(R=25,rks=rks)
            sage: vec_to_int(rectangle_cipher(int_to_vec(0x0, 64))) == 0x2D96E354E8B10874
            True

            sage: rks = [
            ....:   0xffffffffffffffff, 0x0f01fff0fff0f000, 
            ....:   0xfef3fffff000f0f0, 0x0f09f00cf0fff00e,
            ....:   0xf00ff0f5f003c1f0, 0xf914f00ac1f7731f,
            ....:   0xecf0c1f67315a738, 0x3c1b7316a73a536f,
            ....:   0x6f34a738536869cb, 0x9050536c69c30a80,
            ....:   0x00e969cc0a8caf9f, 0x8bd90a84af92baaa,
            ....:   0xdb0caf95baa66b48, 0xa944baa16b45dd65,
            ....:   0xfe186b4fdd6496d0, 0x7facdd6796db1029,
            ....:   0x770d96db102c3f16, 0x98b810243f1dac5b,
            ....:   0xaea73f1cac5bcdcb, 0x9cbaac5bcdc7e462,
            ....:   0x19c1cdc1e46820e5, 0x00d2e46320e5cebb,
            ....:   0x3a7320e3cebab526, 0x5ccaceb0b5255b8c,
            ....:   0x0de2b5225b847fc4, 0x553b5b897fc63b3f
            ....: ]
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rectangle_cipher = RECTANGLE_CVL(R=25,rks=rks)
            sage: vec_to_int(rectangle_cipher(int_to_vec(0xFFFFFFFFFFFFFFFF, 64))) == 0x9945AA34AE3D0112
            True

            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.WORDWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:   solver=SOLVER.SCIP,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options) # optional - scip
            1932 variables and 2133 constraints were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.mps'
            4

            sage: import shutil
            sage: shutil.rmtree("DOCTEST-RECTANGLE-Models")

            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   solver=SOLVER.SCIP,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options) # optional - scip
            7872 variables and 8641 constraints were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.mps'
            10
            
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=2)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   solver=SOLVER.GUROBI,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: # optional - gurobi # optional - espresso
            sage: rectangle_cipher.analyse(model_options)
            4192 variables and 4545 constraints were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.mps'
            4

        Model the cipher with SAT:
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,            
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options) 
            7872 variables and 17473 clauses were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : UNSAT
            [ 10 , 12] (trying w =  11) : SAT
            [ 10 , 11] (trying w =  10) : SAT
            10
            sage: trail = str(rectangle_cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

        Linear cryptanalysis::
            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,            
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options)
            7872 variables and 17217 clauses were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : UNSAT
            [  4 ,  6] (trying w =   5) : UNSAT
            6
            sage: trail = str(rectangle_cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=4)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,            
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options)
            7872 variables and 17217 clauses were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : UNSAT
            [  4 ,  6] (trying w =   5) : UNSAT
            6

            sage: from civerly.cipher_implementations.rectangle import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=5)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,            
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options)
            9712 variables and 21297 clauses were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : SAT
            [  7 ,  8] (trying w =   7) : UNSAT
            8
            sage: trail = str(rectangle_cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.rectangle \
            ....:   import RECTANGLE_CVL
            sage: from civerly.model_options import *
            sage: rectangle_cipher = RECTANGLE_CVL(R=5)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.CADICAL,
            ....:   path=Path("./DOCTEST-RECTANGLE-Models/"))
            sage: rectangle_cipher.analyse(model_options)
            9712 variables and 21617 clauses were written to 'DOCTEST-RECTANGLE-Models/RECTANGLE.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : UNSAT
            [ 13 , 25] (trying w =  19) : SAT
            [ 13 , 19] (trying w =  16) : SAT
            [ 13 , 16] (trying w =  14) : SAT
            [ 13 , 14] (trying w =  13) : UNSAT
            14

            sage: import shutil
            sage: shutil.rmtree("DOCTEST-RECTANGLE-Models", ignore_errors=True)
            """

        if name is None:
            name = "RECTANGLE"

        # RECTANGLE necessites R+1 rks, which are sets by default to zeros
        if rks is None:
            rks = [0] * (R + 1)
        else:
            rks = list(rks)
            assert len(rks) >= R + 1, "RECTANGLE needs R+1=26 roundkeys"
  
        # RECTANGLE S-box specifications
        RECTANGLE_SBOX = (
            0x6, 0x5, 0xC, 0xA,
            0x1, 0xE, 0x7, 0x9,
            0xB, 0x0, 0x3, 0xD,
            0x8, 0xF, 0x4, 0x2
        )

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
        # each column i is contructed as (row_0[i], row_1[i], row_2[i], row_3[i])
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
        transpose = PermuteLayer_CVL(tr, word_coarseness=1, name="Transpose_bitslice_to_nibbles")
        # this function computes the inverse of the permutation
        def invert_perm(p):
            inv = [0] * len(p)
            for src, dst in enumerate(p):
                inv[dst] = src
            return inv
        tr_inv = invert_perm(tr)
        transpose_inv = PermuteLayer_CVL(tr_inv, word_coarseness=1, name="Transpose_nibbles_to_bitslice")
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
        shiftrows = PermuteLayer_CVL(shiftrows_perm_msb(), word_coarseness=1, name="ShiftRows")

        # AddRoundKey
        ark = RoundkeyXOR_CVL(64, 0x0, name="AddRoundKey")
        # One round of RECTANGLE
        rectangle_round = WordSBoxCipher(4, 16, 16, name="RECTANGLE_round")
        st = rectangle_round.IN
        n_ark = rectangle_round.add_subcipher(ark, [(st, (i, i)) for i in range(16)])
        st = rectangle_round.add_subcipher(subcolumn, [(n_ark, (i, i)) for i in range(16)])
        st = rectangle_round.add_subcipher(shiftrows, [(st, (i, i)) for i in range(16)])
        rectangle_round.add_output([(st, (i, i)) for i in range(16)])

        # Full RECTANGLE cipher
        rectangle = WordSBoxCipher(4, 16, 16, name=name)
        st = rectangle.IN
        for r in range(R):
            rectangle_round.nodes[n_ark].const = rks[r]
            st = rectangle.add_subcipher(rectangle_round, [(st, (i, i)) for i in range(16)])

        # final AddRoundKey with K[25]
        ark.const = rks[R]
        st = rectangle.add_subcipher(ark, [(st, (i, i)) for i in range(16)])

        rectangle.add_output([(st, (i, i)) for i in range(16)])
        self.rectangle_cipher = rectangle

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.rectangle_cipher