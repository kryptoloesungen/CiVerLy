from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from sage.crypto.sboxes import GIFT as gift_S

class GIFT128_CVL:
    # Bit permutation specifications with LSB-indexing
    Perm_LSB = [
          0,  33,  66,  99,  96,   1,  34,  67,  64,  97,   2,  35,  32,  65,  98,   3,
          4,  37,  70, 103, 100,   5,  38,  71,  68, 101,   6,  39,  36,  69, 102,   7,
          8,  41,  74, 107, 104,   9,  42,  75,  72, 105,  10,  43,  40,  73, 106,  11,
         12,  45,  78, 111, 108,  13,  46,  79,  76, 109,  14,  47,  44,  77, 110,  15,
         16,  49,  82, 115, 112,  17,  50,  83,  80, 113,  18,  51,  48,  81, 114,  19,
         20,  53,  86, 119, 116,  21,  54,  87,  84, 117,  22,  55,  52,  85, 118,  23,
         24,  57,  90, 123, 120,  25,  58,  91,  88, 121,  26,  59,  56,  89, 122,  27,
         28,  61,  94, 127, 124,  29,  62,  95,  92, 125,  30,  63,  60,  93, 126,  31
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


    def __init__(self, R=40, rks=None, name=None):
        r"""
            EXAMPLES::
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift128 = GIFT128_CVL(R=40) 
                sage: hex(vec_to_int(gift128(int_to_vec(0x0, 128))))
                '0x99999999999999999999999999999999'

            TESTS::
                sage: rks = [
                ....:   0x86660660060606000066006000060008, 0xe6666660660666006066606060066088,
                ....:   0x822646244206060400620024000208cc, 0xa266666462462644606260246002e8cc,
                ....:   0x800666066006060600600006000888ee, 0x8066666660660666606060066088e8e6,
                ....:   0x84022646244206060024000200cc886a, 0xc4226666646246266024600260cce0ea,
                ....:   0x86000666066006060006000000ee08e8, 0xe6006666666066066006600060e6e8e8,
                ....:   0x860402264624420600020044006a88a4, 0xa6442266666462466002604460eae824,
                ....:   0x86060006660660060000006600e8800e, 0x86660066666660666000606660e8608e,
                ....:   0x86060402264624420044006200a4088a, 0xc626442266666462604460626024e882,
                ....:   0x860606000666066000660060000e8808, 0xe60666006666666060666060608ee080,
                ....:   0xc20606040226462400620024008a084c, 0xe246264422666664606260246082e0cc,
                ....:   0xe00606060006660600600006000808e6, 0xe066066600666666606060066080e866,
                ....:   0xa44206060402264600240002004c8062, 0xe4624626442266666024600260cc6062,
                ....:   0x86600606060006660006000000e60068, 0xe66066066600666660066000606660e0,
                ....:   0xc624420606040226000200440062082c, 0xe664624626442266600260446062e0ac,
                ....:   0xe606600606060006000000660068088e, 0xe6666066066600666000606660e0e886,
                ....:   0xa64624420606040200440062002c8802, 0xe6666462462644226044606260ace002,
                ....:   0x866606600606060000660060008e0008, 0xe6666660660666006066606060866088,
                ....:   0x822646244206060400620024000208c4, 0xa266666462462644606260246002e84c,
                ....:   0x800666066006060600600006000880ee, 0x806666666066066660606006608868e6,
                ....:   0x84022646244206060024000200c4886a, 0xc42266666462462660246002604ce0e2
                ....: ]
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift128 = GIFT128_CVL(R=40, rks=rks)
                sage: vec_to_int(gift128(int_to_vec(0xfedcba9876543210fedcba9876543210, 128))) == 0x8422241a6dbf5a9346af468409ee0152
                True


                sage: rks = [
                ....:   0xa666244600002020660620444462066e, 0xe40620024444042464002626602460ca,
                ....:   0xc2664662040000406202006626644eae, 0xe242044026220202664442426006e8a8,
                ....:   0xa02666244600002020444462066eee8e, 0xa4640620024444042626602460caec80,
                ....:   0xc0426646620400000066266446aeea0a, 0x82624204402622024242600660a8e6cc,
                ....:   0xa02026662446000044620666668e28cc, 0x8424640620024444602460426480aeae,
                ....:   0x804042664662040026644626620a88e6, 0x82026242044026226006602066ccca42,
                ....:   0x80202026662446000666660620ccc46a, 0xc4042464062002446042640026ae60ac,
                ....:   0x80004042664662044626620200e62eec, 0xa202026242044026602066444242e886,
                ....:   0x800020202666244666062044446a8e6e, 0xc4440424640620026400262660ace0c2,
                ....:   0x84000040426646626202006626ec4e2e, 0xa622020262420440664442426086e0a8,
                ....:   0xc60000202026662420444462066e6e86, 0x82444404246406202626602460c2ec00,
                ....:   0xe20400004042664600662664462ee202, 0xc0262202026242044242600660a86644,
                ....:   0xa446000020202666446206666686204c, 0xa00244440424640660246042640026a6,
                ....:   0xc662040000404266266446266202086e, 0x8440262202026242600660206644c2ca,
                ....:   0xe62446000020202606666606204c4cea, 0x86200244440424646042640026a6e8a4,
                ....:   0xe64662040000404246266202006eae64, 0xc2044026220202626020664442cae006,
                ....:   0xa6662446000020206606204444ea066e, 0xe4062002444404246400262660a460ca,
                ....:   0xc2664662040000406202006626644ea6, 0xe242044026220202664442426006e828,
                ....:   0xa02666244600002020444462066ee68e, 0xa4640620024444042626602460ca6c80,
                ....:   0xc0426646620400000066266446a6ea0a, 0x8262420440262202424260066028e6c4
                ....:   ]
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.util import int_to_vec, vec_to_int
                sage: gift128 = GIFT128_CVL(R=40, rks=rks)
                sage: vec_to_int(gift128(int_to_vec(0xe39c141fa57dba43f08a85b6a91f86c1, 128))) == 0x13ede67cbdcc3dbf400a62d6977265ea
                True


            Model the cipher with MILP:
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift128_cipher = GIFT128_CVL(R=4)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.WORDWISE,
                ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
                ....:     milp_solver=SOLVER.SCIP,
                ....:     path=Path(tmpdir))
                ....:   gift128_cipher.analyse(model_options) 
                1732 variables and 1837 constraints were written to ...
                4

                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift128_cipher = GIFT128_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:     milp_solver=SOLVER.SCIP,
                ....:     path=Path(tmpdir))
                ....:   gift128_cipher.analyse(model_options) 
                4096 variables and 4673 constraints were written to ...
                3.4150374993
                
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift128_cipher = GIFT128_CVL(R=2)
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
                ....:   gift128_cipher.analyse(model_options) 
                4096 variables and 7297 constraints were written to ...
                3.4150374993

                sage: # optional - gurobi
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: gift128_cipher = GIFT128_CVL(R=2)
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:     milp_solver=SOLVER.GUROBI,
                ....:     path=Path(tmpdir))
                ....:   gift128_cipher.analyse(model_options)
                ....:   gift128_cipher.generate_report(model_options)
                4096 variables and 4673 constraints were written to ...
                3.4150374993
                Output file in: ...

                sage: # optional - gurobi
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: gift128_cipher = GIFT128_CVL(R=2)
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
                ....:   gift128_cipher.analyse(model_options)
                ....:   gift128_cipher.generate_report(model_options)
                4096 variables and 7297 constraints were written to ...
                3.4150374993
                Output file in: ...

            Model the cipher with SAT using different values for ``sat_precision``:

                sage: # optional - cryptominisat, espresso
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: from pathlib import Path
                sage: gift128_cipher = GIFT128_CVL(R=2)
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
                ....:   gift128_cipher.analyse(model_options)
                4096 variables and 10753 clauses were written to ...
                3

                
            Linear Cryptanalysis:
                sage: # optional - cryptominisat # optional - espresso
                sage: from civerly.cipher_implementations.gift128 import GIFT128_CVL
                sage: from civerly.model_options import *
                sage: gift128_cipher = GIFT128_CVL(R=2)
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
                ....:   gift128_cipher.analyse(model_options)
                4032 variables and 9089 clauses were written to ...
                2

            """
        if name is None:
            name = "GIFT128"

        # The default values of the round keys rks are set to 0
        if rks is None:
            rks = [0] * R
        else:
            # If the rks are provided, then we check the number of rks are compatible with the number of rounds
            # If len(rks) < R, then add zero rks 
            # If len(rks) > R, then we consider only the needed number of rks 
            rks = list(rks)
            if len(rks) < R:
                rks = rks + [0] * (R - len(rks))
            elif len(rks) > R:
                rks = rks[:R]

        # SubCells
        # 32 4-bits S-boxes in parallel
        sbox = SBox_CVL(gift_S, name="GIFT128_SBox")
        subcells = WordSBoxCipher(4, 32, 32, name="SubCells")
        for i in range(32):
            node = subcells.add_subcipher(sbox, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        # PermBits
        # First convert the permutation list from LSB to MSB, then perform the bitwise permutation
        perm_msb = self.lsb_to_msb(self.Perm_LSB)
        permbits = PermuteLayer_CVL(perm_msb, word_coarseness=1, name="PermBits128")

        # Implementation of the GIFT128 cipher
        gift = WordSBoxCipher(4, 32, 32, name=name)
        state = gift.IN

        for r in range(R):
            state = gift.add_subcipher(subcells, [(state, (i, i)) for i in range(32)])
            state = gift.add_subcipher(permbits, [(state, (i, i)) for i in range(32)])
            ark = RoundkeyXOR_CVL(128, const=rks[r], name=f"AddRoundKey_{r}")
            state = gift.add_subcipher(ark, [(state, (i, i)) for i in range(32)])

        gift.add_output([(state, (i, i)) for i in range(32)])
        self.gift_cipher = gift

    def __new__(cls, *args, **kwargs):
        """Instantiate a GIFT cipher."""
        instance = super(GIFT128_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.gift_cipher
