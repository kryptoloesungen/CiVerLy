from civerly.cipher import Cipher
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from sage.crypto.sboxes import GIFT as gift_S

class GIFT64_CVL:
    """
    Lightweight CiVerLy implementation of the GIFT-64 block cipher.

    This implementation models:
    - the substitution layer SubCells
    - the permutation layer PermBits
    - the round key addition AddRoundKey
    """
    # Bit permutation specifications with LSB-indexing
    Perm_LSB = [
        0, 17, 34, 51, 48,  1, 18, 35, 32, 49,  2, 19, 16, 33, 50,  3,
        4, 21, 38, 55, 52,  5, 22, 39, 36, 53,  6, 23, 20, 37, 54,  7,
        8, 25, 42, 59, 56,  9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
        12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15
    ]
    @staticmethod
    def lsb_to_msb(permutation_lsb):
        """
        Since this implementation is based on the C reference implementation, which uses LSB indexing, 
        we have to convert it to MSB indexing to be compatible with the original paper.
        To this end, we reverse the indexing, where the bit index 0 would correspond 
        to the MSB, instead of the LSB. 
        """
        n = len(permutation_lsb)
        permutation_msb = [0] * n
        for i in range(n):
            permutation_msb[n - 1 - i] = (n - 1) - permutation_lsb[i]
        return permutation_msb

    def __init__(self, R=28, rks=None, name=None):
        
        r"""
            EXAMPLES::
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift64 = GIFT64_CVL(R=28)  
                sage: hex(vec_to_int(gift64(int_to_vec(0x0, 64))))
                '0x0'


            TESTS::
                sage: rks = [
                ....:   0x8000000000000008, 0x8000000000000088, 0x8000000000000888,
                ....:   0x8000000000008888, 0x8000000000088888, 0x8000000000888880,
                ....:   0x8000000000888808, 0x8000000000888088, 0x8000000000880888,
                ....:   0x8000000000808888, 0x8000000000088880, 0x8000000000888800,
                ....:   0x8000000000888008, 0x8000000000880088, 0x8000000000800888,
                ....:   0x8000000000008880, 0x8000000000088808, 0x8000000000888080,
                ....:   0x8000000000880808, 0x8000000000808088, 0x8000000000080880,
                ....:   0x8000000000808800, 0x8000000000088000, 0x8000000000880000,
                ....:   0x8000000000800008, 0x8000000000000080, 0x8000000000000808,
                ....:   0x8000000000008088
                ....: ]
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift64 = GIFT64_CVL(R=28, rks=rks)
                sage: vec_to_int(gift64(int_to_vec(0x0, 64))) == 0xf62bc3ef34f775ac
                True


                sage: rks = [
                ....:   0x8233023002030208, 0xb233323032033288, 0x8233023002030a88,
                ....:   0xb23332303203ba88, 0x80122203200a8a9b, 0x9032322330aa9ab3,
                ....:   0x80122203208a8a1b, 0x9032322330aa92bb, 0x8201022202b90a9a,
                ....:   0xb201322232b1ba9a, 0x8201022202398a92, 0xb201322232b9ba12,
                ....:   0x82020013229aa00b, 0x9222103332ba30ab, 0x820200132292288b,
                ....:   0x922210333232b8a3, 0x82130210022b8a28, 0xb213321032abb2a0,
                ....:   0x8213021002ab0a28, 0xb213321032a3b2a8, 0xa0120203000a2a93,
                ....:   0xb032122310a2ba33, 0xa0120203000aa213, 0xb032122310aa3233,
                ....:   0x822102020291023a, 0xb2213202321132b2, 0x8221020202110a3a,
                ....:   0xb22132023211b2ba
                ....: ]
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift64 = GIFT64_CVL(R=28, rks=rks)
                sage: vec_to_int(gift64(int_to_vec(0xfedcba9876543210, 64))) == 0xc1b71f66160ff587
                True


                sage: rks = [
                ....:   0xa300032213120119, 0xb13101123333319b, 0xa032033120232a99,
                ....:   0xa13322132003999a, 0x81221112231b8b88, 0x8330311113bbbbb1,
                ....:   0x8131220320b9aa3a, 0x8231222313b88399, 0x9110231103aa0b8a,
                ....:   0xb11331311193abba, 0xa20120330238a9b3, 0x80033132239ba813,
                ....:   0x83110122018ab31a, 0xb3311331219813bb, 0xa2330030239328a9,
                ....:   0x9310033122338aa1, 0x8302010033188b3b, 0xb333211231b99193,
                ....:   0xa032231120ab0a39, 0xa113001320a3b39a, 0xa3021310013b0982,
                ....:   0x8332333113b1b911, 0xa13122230039a212, 0x8231020113b82333,
                ....:   0x9332031301802308, 0x91133333311321b0, 0x822120332210293b,
                ....:   0xa20331120113a0bb
                ....: ]
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift64 = GIFT64_CVL(R=28, rks=rks)
                sage: vec_to_int(gift64(int_to_vec(0xc450c7727a9b8a7d, 64))) == 0xe3272885fa94ba8b
                True

            Model the cipher with MILP:
                
                sage: # optional - scip
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift64_cipher = GIFT64_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.WORDWISE,
                ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
                ....:     milp_solver=SOLVER.SCIP,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options) 
                482 variables and 503 constraints were written to ...
                2
                
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift64_cipher = GIFT64_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:     milp_solver=SOLVER.SCIP,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options) 
                2048 variables and 2337 constraints were written to ...
                3.4150374993
                
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift64_cipher = GIFT64_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
                ....:     milp_solver=SOLVER.SCIP,
                ....:     logic_minimizer=SOLVER.ESPRESSO,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options) 
                2048 variables and 3649 constraints were written to ...
                3.4150374993

                
                sage: # optional - gurobi
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: gift64_cipher = GIFT64_CVL(R=4)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:     milp_solver=SOLVER.GUROBI,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options)
                ....:   gift64_cipher.generate_report(model_options)
                3712 variables and 4353 constraints were written to ...
                11.4150374993
                Output file in: ...

                
                sage: # optional - gurobi
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: gift64_cipher = GIFT64_CVL(R=4)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
                ....:     milp_solver=SOLVER.GUROBI,
                ....:     logic_minimizer=SOLVER.ESPRESSO,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options)
                ....:   gift64_cipher.generate_report(model_options)
                3712 variables and 6977 constraints were written to ...
                11.4150374993
                Output file in: ...
                
                
            Model the cipher with SAT using different values for ``sat_precision``:
   
                sage: # optional - cryptominisat, espresso
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift64_cipher = GIFT64_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.SAT,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
                ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
                ....:     sat_solver=SOLVER.CRYPTOMINISAT,
                ....:     logic_minimizer=SOLVER.ESPRESSO,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options)
                2048 variables and 5377 clauses were written to ...
                3

                sage: # optional - cryptominisat, espresso
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift64_cipher = GIFT64_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.SAT,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
                ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
                ....:     solve_range=(0, 10),
                ....:     sat_precision=1,
                ....:     sat_solver=SOLVER.CRYPTOMINISAT,
                ....:     logic_minimizer=SOLVER.ESPRESSO,
                ....:     path=Path(tmpdir))
                ....:   gift64_cipher.analyse(model_options)
                2048 variables and 5377 clauses were written to ...
                3.4

                sage: # optional - cadical # optional - espresso
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift64_cipher = GIFT64_CVL(R=4)
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
                ....:   gift64_cipher.analyse(model_options)
                ....:   trail = str(gift64_cipher.get_trail(model_options))
                ....:   assert "Unnamed Component" not in trail
                3712 variables and 10113 clauses were written to ...
                11


            Linear cryptanalysis::

                sage: # optional - cryptominisat # optional - espresso
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: gift64_cipher = GIFT64_CVL(R=4)
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
                ....:   gift64_cipher.analyse(model_options)
                ....:   trail = str(gift64_cipher.get_trail(model_options))
                ....:   assert "Unnamed Component" not in trail
                3648 variables and 8449 clauses were written to ...
                5

                sage: # optional - cryptominisat # optional - espresso
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: gift64_cipher = GIFT64_CVL(R=4)
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
                ....:   gift64_cipher.analyse(model_options)
                3648 variables and 8449 clauses were written to ...
                5

                sage: # optional - cryptominisat # optional - espresso
                sage: from civerly.cipher_implementations.gift64 import GIFT64_CVL
                sage: from civerly.model_options import *
                sage: gift64_cipher = GIFT64_CVL(R=5)
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
                ....:   gift64_cipher.analyse(model_options)
                ....:   trail = str(gift64_cipher.get_trail(model_options))
                ....:   assert "Unnamed Component" not in trail
                4464 variables and 10401 clauses were written to ...
                7

            """

        if name is None:
            name = "GIFT64"
        
        # The default values of the round keys rks are set to 0
        if rks is None:
            rks = [0] * R
        else:
            # If the rks are provided, then we check if the number of rks are compatible with the number of rounds
            # If len(rks) < R, then add zero rks 
            # If len(rks) > R, then we consider only the needed number of rks 
            rks = list(rks)
            if len(rks) < R:
                rks = rks + [0] * (R - len(rks))
            elif len(rks) > R:
                rks = rks[:R]
        
        # SubCells
        # 16 4-bits S-boxes in parallel
        sbox = SBox_CVL(gift_S, name="GIFT64_SBox")
        subcells = WordSBoxCipher(4, 16, 16, name="SubCells")
        for i in range(16):
            node = subcells.add_subcipher(sbox, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        # PermBits
        # First convert the permutation list from LSB to MSB, then perform the bitwise permutation
        perm_msb = self.lsb_to_msb(self.Perm_LSB)
        permbits = PermuteLayer_CVL(perm_msb, word_coarseness=1, name="PermBits64")

        # Implementation of the GIFT64 cipher
        gift = WordSBoxCipher(4, 16, 16, name=name)
        state = gift.IN
        
        for r in range(R):
            state = gift.add_subcipher(subcells, [(state, (i, i)) for i in range(16)])
            state = gift.add_subcipher(permbits, [(state, (i, i)) for i in range(16)])
            ark = RoundkeyXOR_CVL(64, const=rks[r], name=f"AddRoundKey_{r}")
            state = gift.add_subcipher(ark, [(state, (i, i)) for i in range(16)])

        gift.add_output([(state, (i, i)) for i in range(16)])
        self.gift_cipher = gift

    def __new__(cls, *args, **kwargs):
        instance = super(GIFT64_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.gift_cipher