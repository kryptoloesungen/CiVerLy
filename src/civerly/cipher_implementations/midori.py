'''
Docstring for civerly.cipher_implementations.midori
Midori is a family of 2 block ciphers: Midori64 and Midori 128.
They both accept key length of 128 bits.
It is a SPN cipher and consists of S-layer (SubCell) and P-layer (ShuffleCell & MixColumn) and KeyAdd 
The state is represented by a 4x4 matrix
Midori64:
    block size  of 64 bits
    key length of 128 bits 
    cell size in the 4x4 matrix is 4 bits
    number of rounds is 16
    Sb0[x]
Midori128:
    block size  of 64 bits
    key length of 128 bits
    cell size in the 4x4 matrix is 8 bits
    number of rounds is 20
    Sb1[x]
    uses 4 different 8-bit S-Boxes: SSb0, SSb1, SSb2 and SSb3

SubCell:
    Midori64:
        Sb0 is applied to every 4-bit cell of the state in parallel
        si ← Sb0[si]
    Midori128:
        SSBi are applied to every 8-bit cell of the state in parallel
        si ← SSb(i mod 4)[si] 0 <= i <= 15

ShuffleCell:
    Midori64 & Midori128:
        (s0, s1, ..., s15) ← (s0, s10, s5, s15, s14, s4, s11, s1, s9, s3, s12, s6, s7, s13, s2, s8)

MixColumn:
    Midori64 & Midori128:
        M is applied to every 4m bit column of the state
        t(si, si+1, si+2, si+3) ← M(t)*(si, si+1, si+2, si+3) and i = 0, 4, 8, 12
KeyAdd:
    Midori64 & Midori128:
        The ith n-bit round key RKi is XORed to a state S

Function:
    keyAdd(X,Wk)
    for i= 0..R-2
        SubCell(S)
        ShuffleCell(S)
        MixColumn(S)
        KeyAdd(S)
    SubCell(S)
    KeyAdd(S, WK)
'''
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL, LinearLayer_CVL
from civerly.aeslike import AESlike

from sage.crypto.sbox import SBox as SBox_sage
from sage.matrix.special import zero_matrix, identity_matrix, block_matrix
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori64_cipher = MIDORI64_CVL(R=10)
            sage: hex(vec_to_int(midori64_cipher(int_to_vec(0xabcd1234, 64))))
            '0x13b622dcaa65dbc3'
            

        TESTS::

        Using test vectors from the original specification (see Appendix A
        in https://eprint.iacr.org/2015/1142.pdf):

            sage: rks = [
            ....:   0x0000000000000000, 0x0001010110110011, 0x0111100011000000,
            ....:   0x1010010000110101, 0x0110001000010011, 0x0001000001001111,
            ....:   0x1101000101110000, 0x0000001001100110, 0x0000101111001100,
            ....:   0x1001010010000001, 0x0100000010111000, 0x0111000110010111,
            ....:   0x0010001010001110, 0x0101000100110000, 0x1111100011001010,
            ....:   0x1101111110010000, 0x0000000000000000
            ....: ]
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori64_cipher = MIDORI64_CVL(R=16,rks=rks)
            sage: vec_to_int(midori64_cipher(int_to_vec(0x42c20fd3b586879e, 64))) == 0x66bcdc6270d901cd
            True
        
        Model the cipher with MILP: 

            sage: # optional - scip
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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
            sage: from civerly.cipher_implementations.midori import MIDORI64_CVL
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

class MIDORI128_CVL:
    #Sb1 to construct SSb0, SSb1, SSb2 and SSb3
    SB1 = [0x1, 0x0, 0x5, 0x3, 0xE, 0x2, 0xF, 0x7, 0xD, 0xA, 0x9, 0xB, 0xC, 0x8, 0x4, 0x6]
    
    #ShuffleCell permutation
    SHUFFLE = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
    #MixColumn matrix
    M = [
        [0, 1, 1, 1],
        [1, 0, 1, 1],
        [1, 1, 0, 1], 
        [1, 1, 1, 0],
    ]
 
    def __init__(self, R=20, rks=None, name=None): 
        r"""
        EXAMPLES:
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori128_cipher = MIDORI128_CVL(R=10)
            sage: hex(vec_to_int(midori128_cipher(int_to_vec(0x000000000000000000000000abcd1234, 128))))
            '0x93d8058b48f3c7098c74c2cedb814be9'

        TESTS::

        Using test vectors from the original specification (see Appendix A
        in https://eprint.iacr.org/2015/1142.pdf):
        
            sage: rks = [
            ....:   0x00000000000000000000000000000000, 0x00000001000100010100010100000101,
            ....:   0x00010101010000000101000000000000, 0x01000100000100000000010100010001,
            ....:   0x00010100000001000000000100000101, 0x00000001000000000001000001010101,
            ....:   0x01010001000000010001010100000000, 0x00000000000001000001010000010100,
            ....:   0x00000000010001010101000001010000, 0x01000001000100000100000000000001,
            ....:   0x00010000000000000100010101000000, 0x00010101000000010100000100010101,
            ....:   0x00000100000001000100000001010100, 0x00010001000000010000010100000000,
            ....:   0x01010101010000000101000001000100, 0x01010001010101010100000100000000,
            ....:   0x00010101010100000100000000000001, 0x00000001010100000000010000010000,
            ....:   0x00000100000001010100010100010000, 0x00010100000001000100000001000100,
            ....:   0x00000000000000000000000000000000
            ....: ]
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori128_cipher = MIDORI128_CVL(R=20,rks=rks)
            sage: vec_to_int(midori128_cipher(int_to_vec(0x00000000000000000000000000000000, 128))) == 0xc055cbb95996d14902b60574d5e728d6
            True

            sage: rks = [
            ....:   0x687ded3b3c85b3f35b1009863e2a8cbf, 0x687ded3a3c84b3f25a1008873e2a8dbe,
            ....:   0x687cec3a3d85b3f35a1109863e2a8cbf, 0x697dec3b3c84b3f35b1008873e2b8cbe,
            ....:   0x687cec3b3c85b2f35b1009873e2a8dbe, 0x687ded3a3c85b3f35b1109863f2b8dbe,
            ....:   0x697ced3a3c85b3f25b1108873e2a8cbf, 0x687ded3b3c85b2f35b1108863e2b8dbf,
            ....:   0x687ded3b3d85b2f25a1109863f2b8cbf, 0x697ded3a3c84b3f35a1009863e2a8cbe,
            ....:   0x687ced3b3c85b3f35a1008873f2a8cbf, 0x687cec3a3c85b3f25a1009873e2b8dbe,
            ....:   0x687dec3b3c85b2f35a1009863f2b8dbf, 0x687ced3a3c85b3f25b1008873e2a8cbf,
            ....:   0x697cec3a3d85b3f35a1109863f2a8dbf, 0x697ced3a3d84b2f25a1009873e2a8cbf,
            ....:   0x687cec3a3d84b3f35a1009863e2a8cbe, 0x687ded3a3d84b3f35b1008863e2b8cbf,
            ....:   0x687dec3b3c85b2f25a1008873e2b8cbf, 0x687cec3b3c85b2f35a1009863f2a8dbf,
            ....:   0x687ded3b3c85b3f35b1009863e2a8cbf
            ....: ]
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: midori128_cipher = MIDORI128_CVL(R=20,rks=rks)
            sage: vec_to_int(midori128_cipher(int_to_vec(0x51084ce6e73a5ca2ec87d7babc297543, 128))) == 0x1e0ac4fddff71b4c1801b73ee4afc83d
            True

        Model the cipher with MILP: 

            sage: # optional - scip
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: midori128_cipher = MIDORI128_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   midori128_cipher.analyse(model_options) #optional - scip
            ....:   midori128_cipher.generate_report(model_options)
            1260 variables and 1317 constraints were written to ...
            16
            Output file in: ...

            sage: # optional - scip
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.model_options import *
            sage: midori128_cipher = MIDORI128_CVL(R=8)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   midori128_cipher.analyse(model_options)
            ....:   midori128_cipher.generate_report(model_options)
            2556 variables and 2709 constraints were written to ...
            32
            Output file in...

        Using SAT modeling::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.model_options import *
            sage: midori128_cipher = MIDORI128_CVL(R=3)
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
            ....:   midori128_cipher.analyse(model_options)
            ....:   trail = str(midori128_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            7712 variables and 47845 clauses were written to ...
            14
        
        Linear cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.midori import MIDORI128_CVL
            sage: from civerly.model_options import *
            sage: midori128_cipher = MIDORI128_CVL(R=3)
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
            ....:   midori128_cipher.analyse(model_options)
            ....:   trail = str(midori128_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            7616 variables and 70549 clauses were written to ...
            7

        """
        if name is None:
            name = "MIDORI128"

        if rks is None:
            rks = [0]  * (R+1)
        if len(rks) != R + 1:
            raise ValueError(f"Midori128 expects rks of length R+1")
      
        #SubCell 
        sb1 = self.SB1
        def apply_sb1_on_nibbles(x):
            lo = x & 0x0F
            hi = (x >> 4) & 0x0F
            return (sb1[lo] ^ (sb1[hi] << 4)) & 0xFF

        def ssb0(x):
            # Mirrors the C reference SSb0 bit-permutation -> Sb1-on-nibbles -> bit-permutation
            x = ((x & 0x80) >> 4) | ((x & 0x40) >> 0) | ((x & 0x20) >> 4) | ((x & 0x10) >> 0) | \
                ((x & 0x08) << 4) | ((x & 0x04) << 0) | ((x & 0x02) << 4) | ((x & 0x01) << 0)
            x = apply_sb1_on_nibbles(x)
            x = ((x & 0x80) >> 4) | ((x & 0x40) >> 0) | ((x & 0x20) >> 4) | ((x & 0x10) << 0) | \
                ((x & 0x08) << 4) | ((x & 0x04) << 0) | ((x & 0x02) << 4) | ((x & 0x01) << 0)
            return x

        def ssb1(x):
            x = ((x & 0x80) >> 3) | ((x & 0x40) << 1) | ((x & 0x20) >> 3) | ((x & 0x10) >> 3) | \
                ((x & 0x08) >> 3) | ((x & 0x04) << 1) | ((x & 0x02) << 5) | ((x & 0x01) << 5)
            x = apply_sb1_on_nibbles(x)
            x = ((x & 0x80) >> 1) | ((x & 0x40) >> 5) | ((x & 0x20) >> 5) | ((x & 0x10) << 3) | \
                ((x & 0x08) >> 1) | ((x & 0x04) << 3) | ((x & 0x02) << 3) | ((x & 0x01) << 3)
            return x

        def ssb2(x):
            x = ((x & 0x80) >> 6) | ((x & 0x40) >> 2) | ((x & 0x20) << 2) | ((x & 0x10) << 2) | \
                ((x & 0x08) << 2) | ((x & 0x04) >> 2) | ((x & 0x02) << 2) | ((x & 0x01) << 2)
            x = apply_sb1_on_nibbles(x)
            x = ((x & 0x80) >> 2) | ((x & 0x40) >> 2) | ((x & 0x20) >> 2) | ((x & 0x10) << 2) | \
                ((x & 0x08) >> 2) | ((x & 0x04) >> 2) | ((x & 0x02) << 6) | ((x & 0x01) << 2)
            return x

        def ssb3(x):
            x = ((x & 0x80) >> 5) | ((x & 0x40) >> 1) | ((x & 0x20) >> 1) | ((x & 0x10) >> 1) | \
                ((x & 0x08) << 3) | ((x & 0x04) >> 1) | ((x & 0x02) >> 1) | ((x & 0x01) << 7)
            x = apply_sb1_on_nibbles(x)
            x = ((x & 0x80) >> 7) | ((x & 0x40) >> 3) | ((x & 0x20) << 1) | ((x & 0x10) << 1) | \
                ((x & 0x08) << 1) | ((x & 0x04) << 5) | ((x & 0x02) << 1) | ((x & 0x01) << 1)
            return x

        SSb0 = [ssb0(x) for x in range(256)]
        SSb1 = [ssb1(x) for x in range(256)]
        SSb2 = [ssb2(x) for x in range(256)]
        SSb3 = [ssb3(x) for x in range(256)]

        ssb0_cvl = SBox_CVL(SBox_sage(SSb0), name="SSb0")
        ssb1_cvl = SBox_CVL(SBox_sage(SSb1), name="SSb1")
        ssb2_cvl = SBox_CVL(SBox_sage(SSb2), name="SSb2")
        ssb3_cvl = SBox_CVL(SBox_sage(SSb3), name="SSb3")
        ssb_by_col = [ssb0_cvl, ssb1_cvl, ssb2_cvl, ssb3_cvl]

        subcells = WordSBoxCipher(8, 16, 16, name="SubCell")
        for i in range(16):
            sb = ssb_by_col[i%4]
            node = subcells.add_subcipher(sb, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        #ShuffleCell same as Midori64
        def inv_perm(p):
            inv = [0] * len(p)
            for i, j in enumerate(p):
                inv[j] = i
            return inv
        shuffle = PermuteLayer_CVL(inv_perm(self.SHUFFLE), word_coarseness=8, name="ShuffleCell")

        #MixColumn
        I = identity_matrix(GF(2), 8)
        O = zero_matrix(GF(2), 8)
        MC = []
        for r in range(4):
            row = []
            for c in range(4):
                row.append(I if MIDORI128_CVL.M[r][c] == 1 else O)
            MC.append(row)
        MC_matrix = block_matrix(GF(2), MC, subdivide=False) 
        mc_layer = LinearLayer_CVL(MC_matrix, branch_number_differential=4, branch_number_linear=4, name="MixColumn")

        # Apply MixColumn to each ROW block (indices 4*row + k)
        mc_layers = AESlike(8, rows=4, cols=4, name="MixColumnLayer")
        for row in range(4):
            node = mc_layers.add_subcipher(
                mc_layer,
                [(mc_layers.IN, (4*row + k, k)) for k in range(4)]
            )
            mc_layers.add_output([(node, (k, 4*row + k)) for k in range(4)])

        #Full cipher
        midori = WordSBoxCipher(8, 16, 16, name=name)
        state = midori.IN

        #Initial keyAdd 0
        ark0 = RoundkeyXOR_CVL(128, const=rks[0], name="KeyAdd_0")
        state = midori.add_subcipher(ark0, [(state, (i,i)) for i in range(16)])

        #Rounds 0..R-2
        for r in range(R-1):
            state = midori.add_subcipher(subcells, [(state, (i,i)) for i in range(16)]) 
            state = midori.add_subcipher(shuffle, [(state, (i,i)) for i in range(16)]) 
            state = midori.add_subcipher(mc_layers, [(state, (i,i)) for i in range(16)]) 
            ark = RoundkeyXOR_CVL(128, const=rks[r+1], name=f"KeyAdd_RK{r}")    
            state = midori.add_subcipher(ark, [(state, (i,i)) for i in range(16)]) 

        #Final SubCell
        state = midori.add_subcipher(subcells, [(state, (i,i)) for i in range(16)]) 

        #Final keyAdd 19
        arkf = RoundkeyXOR_CVL(128, const=rks[R], name="KeyAdd_19")
        state = midori.add_subcipher(arkf, [(state, (i,i)) for i in range(16)]) 

        midori.add_output([(state, (i,i)) for i in range(16)])
        self.midori_cipher = midori

    def __new__(cls, *args, **kwargs):
        instance = super(MIDORI128_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.midori_cipher
