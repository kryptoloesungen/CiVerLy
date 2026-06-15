from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL, LinearLayer_CVL
from civerly.aeslike import AESlike

from sage.crypto.sbox import SBox as SBox_sage
from sage.matrix.special import identity_matrix, zero_matrix, block_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

class MIDORI64_CVL:
    #Sb_0 specifications
    SB0 = (
        0xC, 0xA, 0xD, 0x3,
        0xE, 0xB, 0xF, 0x7,
        0x8, 0x9, 0x1, 0x5,
        0x0, 0x2, 0x4, 0x6
    )
    #ShuffleCell permutation matrix 
    SHUFFLE = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
    # Binary permutation MixColumn matrix
    M = [
        [0, 1, 1, 1],
        [1, 0, 1, 1],
        [1, 1, 0, 1], 
        [1, 1, 1, 0],
    ]
  
    def __init__(self, R=16, rks=None, name=None): 
        r"""
        EXAMPLES:
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori64_cipher = MIDORI64_CVL(R=10)
            sage: hex(vec_to_int(midori64_cipher(int_to_vec(0xabcd1234, 64))))
            '0x13b622dcaa65dbc3'

        TESTS::
            sage: rks = [
            ....:   0x0000000000000000, 0x0001010110110011, 0x0111100011000000,
            ....:   0x1010010000110101, 0x0110001000010011, 0x0001000001001111,
            ....:   0x1101000101110000, 0x0000001001100110, 0x0000101111001100,
            ....:   0x1001010010000001, 0x0100000010111000, 0x0111000110010111,
            ....:   0x0010001010001110, 0x0101000100110000, 0x1111100011001010,
            ....:   0x1101111110010000, 0x0000000000000000
            ....: ]
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori64_cipher = MIDORI64_CVL(R=16,rks=rks)
            sage: vec_to_int(midori64_cipher(int_to_vec(0x0000000000000000, 64))) == 0x3c9cceda2bbd449a
            True


            sage: rks = [
            ....:   0x336de4bd02af3f4c, 0x687cec3a2c94b3e2, 0x5a0119862f2a8cbf,
            ....:   0x786dec3b3c94b2f2, 0x5a0009963e2b8cae, 0x687ced3b3d85a2e2,
            ....:   0x4a1109873f3b8cbf, 0x687ded2b3d95b2e3, 0x5b1019972f2a9dbf,
            ....:   0x787cec3b2c85b3f2, 0x5a1009862e3b9cbf, 0x696ced3a2c84b2e2,
            ....:   0x5b0009962e2a9daf, 0x697ced3a3c94b3f3, 0x4a0119862f2a9caf,
            ....:   0x797cfc2a2c84b3f3, 0x336de4bd02af3f4c
            ....: ]
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori64_cipher = MIDORI64_CVL(R=16,rks=rks)
            sage: vec_to_int(midori64_cipher(int_to_vec(0x42c20fd3b586879e, 64))) == 0x66bcdc6270d901cd
            True
        
        Model the cipher with MILP: 

            sage: # optional - scip
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: midori64_cipher = MIDORI64_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   midori64_cipher.analyse(model_options)
            ....:   midori64_cipher.generate_report(model_options)
            1260 variables and 1317 constraints were written to ...
            16
            Output file in: ...

            sage: # optional - scip
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: midori64_cipher = MIDORI64_CVL(R=8)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   midori64_cipher.analyse(model_options)
            ....:   midori64_cipher.generate_report(model_options)
            2556 variables and 2709 constraints were written to ...
            32
            Output file in: ...

            sage: # optional - scip
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: midori64_cipher = MIDORI64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   midori64_cipher.analyse(model_options)
            2656 variables and 2881 constraints were written to ...
            8


            sage: # optional - gurobi
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: midori64_cipher = MIDORI64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path("./DOCTEST-MIDORI64-Models/"))
            ....:   midori64_cipher.analyse(model_options) # long
            2656 variables and 4065 constraints were written to ...
            8

        Using SAT modeling::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: midori64_cipher = MIDORI64_CVL(R=3)
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
            ....:   midori64_cipher.analyse(model_options)
            ....:   trail = str(midori64_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3856 variables and 10417 clauses were written to ...
            14
        
        Linear cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: midori64_cipher = MIDORI64_CVL(R=3)
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
            ....:   midori64_cipher.analyse(model_options)
            ....:   trail = str(midori64_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3856 variables and 10129 clauses were written to ...
            7
            
            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.midori64 import MIDORI64_CVL
            sage: from civerly.model_options import *
            sage: midori64_cipher = MIDORI64_CVL(R=3)
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
            ....:   midori64_cipher.analyse(model_options)
            ....:   trail = str(midori64_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3984 variables and 10129 clauses were written to ...
            48

        """
        if name is None:
            name = "MIDORI64"

        if rks is None:
            rks = [0]  * (R+1)
        else:
            # If the rks are provided, then we check if the number of rks are compatible with the number of rounds
            # If len(rks) < R, then add zero rks 
            # If len(rks) > R, then we consider only the needed number of rks 
            rks = list(rks)
            if len(rks) < (R+1):
                rks = rks + [0] * ((R+1) - len(rks))
            elif len(rks) > (R+1):
                rks = rks[:(R+1)]
        
        #SubCell
        sb0 = SBox_CVL(SBox_sage(MIDORI64_CVL.SB0), name="Sb0")
        subcells = WordSBoxCipher(4, 16, 16, name="SubCell")
        for i in range(16):
            node = subcells.add_subcipher(sb0, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        #ShuffleCell
        def inv_perm(p):
            inv = [0] * len(p)
            for i, j in enumerate(p):
                inv[j] = i
            return inv
        shuffle_cell = PermuteLayer_CVL(inv_perm(MIDORI64_CVL.SHUFFLE), word_coarseness=4, name="ShuffleCell")

        #MixColum
        I = identity_matrix(GF(2), 4)
        MC = []
        for r in range(4):
            row = []
            for c in range(4):
                row.append(I if MIDORI64_CVL.M[r][c] == 1 else 0)
            MC.append(row)

        MC_matrix = block_matrix(GF(2), MC, subdivide=False)
        mc_layer = LinearLayer_CVL(MC_matrix, branch_number_differential=4, branch_number_linear=4, name="MixColumn")

        #Apply MixColumn to 4 columns indep
        mc_layers = AESlike(4, rows=4, cols=4, name="MixColumnLayer")
        for rows in range(4):
            # column indices in the 16-nibble state are:
            # (0+col, 4+col, 8+col, 12+col) == (col + 4*k) for k=0..3
            node = mc_layers.add_subcipher(mc_layer, [(mc_layers.IN, (4*rows + k, k)) for k in range(4)]) 
            mc_layers.add_output([(node, (k, 4*rows + k)) for k in range(4)])

        #Full cipher
        midori = WordSBoxCipher(4, 16, 16, name=name)
        state = midori.IN

        #Initial keyAdd 0
        ark0 = RoundkeyXOR_CVL(64, const=rks[0], name="KeyAdd_0")
        state = midori.add_subcipher(ark0, [(state, (i,i)) for i in range(16)])

        #Rounds 0..R-2
        for r in range(R-1):
            state = midori.add_subcipher(subcells, [(state, (i,i)) for i in range(16)]) 
            state = midori.add_subcipher(shuffle_cell, [(state, (i,i)) for i in range(16)]) 
            state = midori.add_subcipher(mc_layers, [(state, (i,i)) for i in range(16)]) 
            ark = RoundkeyXOR_CVL(64, const=rks[r+1], name=f"KeyAdd_RK{r}")    
            state = midori.add_subcipher(ark, [(state, (i,i)) for i in range(16)]) 

        #Final SubCell
        state = midori.add_subcipher(subcells, [(state, (i,i)) for i in range(16)]) 

        #Final keyAdd 15
        arkf = RoundkeyXOR_CVL(64, const=rks[R], name="KeyAdd_15")
        state = midori.add_subcipher(arkf, [(state, (i,i)) for i in range(16)]) 

        midori.add_output([(state, (i,i)) for i in range(16)])
        self.midori_cipher = midori

    def __new__(cls, *args, **kwargs):
        instance = super(MIDORI64_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.midori_cipher
