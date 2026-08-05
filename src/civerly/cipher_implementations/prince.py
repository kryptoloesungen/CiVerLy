from sage.crypto.sboxes import PRINCE as prince_S
from sage.matrix.special import zero_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.component import LinearLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.wordsboxcipher import WordSBoxCipher

F2 = GF(2)

# The matrix M' is 16x16 matrix over GF(2) acting on 16 nibbles in hex format
# each entry is a 4x4 binary submatrix
# M' is constructed following the method depicted in the original paper
M_ = [
    [
        0x0111,
        0x2220,
        0x4404,
        0x8088,
        0x1011,
        0x0222,
        0x4440,
        0x8808,
        0x1101,
        0x2022,
        0x0444,
        0x8880,
        0x1110,
        0x2202,
        0x4044,
        0x0888,
    ],
    [
        0x1110,
        0x2202,
        0x4044,
        0x0888,
        0x0111,
        0x2220,
        0x4404,
        0x8088,
        0x1011,
        0x0222,
        0x4440,
        0x8808,
        0x1101,
        0x2022,
        0x0444,
        0x8880,
    ],
]


# This helper function performs a multiplication over GF(2)
# of a 16-bit vector with a 16x16 binary matrix
# For correctness purposes, out & 0xFFFF ensures that length of
# the output is 16-bit, while converting to LSB-indexing to match the
# original paper specifications and test vectors
def vec_mat_mult(vec, mat):
    out = 0
    for i in range(16):
        if (vec >> i) & 1:
            out ^= mat[i]
    return out & 0xFFFF


# This function implements M' by computing each column of the matrix.
# To this end, we multiply M_ with a internal state column
def m_prime_layer(x):
    M_0 = vec_mat_mult((x >> 0) & 0xFFFF, M_[0])
    M_1 = vec_mat_mult((x >> 16) & 0xFFFF, M_[1])
    M_2 = vec_mat_mult((x >> 32) & 0xFFFF, M_[1])
    M_3 = vec_mat_mult((x >> 48) & 0xFFFF, M_[0])
    return (M_3 << 48) | (M_2 << 32) | (M_1 << 16) | M_0


# This function applies a shift row, similar to AES shift
# Each row is shifted by its row index
# Since the internal state is a 4x4 nibble, where each nibble is 16 bits
# Shifting one row means shifting by 16 bits x row index
# First row is not shifted, the second row is shifted by 1x16 bits
# Third row is shifted by 2x16 bits, the last row is shifted by 3x16 bits
def shift_rows(x, inverse=False):
    row_mask = 0xF000F000F000F000
    out = x & row_mask
    for i in range(1, 4):
        row = x & (row_mask >> (4 * i))
        shift = i * 16 if inverse else (64 - i * 16)
        shift %= 64
        out |= ((row >> shift) | (row << (64 - shift))) & ((1 << 64) - 1)
    return out


def m_layer(x):
    return shift_rows(m_prime_layer(x), inverse=False)


def m_inv_layer(x):
    return m_prime_layer(shift_rows(x, inverse=True))


# This function builds a 64x64 matrix by converting back to MSB-indexing
def build_matrix(f):
    A = zero_matrix(F2, 64, 64)
    for j in range(64):
        x = 1 << (63 - j)
        y = f(x)
        for i in range(64):
            A[i, j] = (y >> (63 - i)) & 1
    return A


Mprime_ = build_matrix(m_prime_layer)
M_layer = build_matrix(m_layer)
Minv_ = build_matrix(m_inv_layer)


class PRINCE_CVL:
    def __init__(self, R=12, rks=None, name="PRINCE"):
        r"""
        CiVerLy implementation of PRINCE (https://eprint.iacr.org/2012/529.pdf).
        It takes the following arguments:

            - ``R`` -- integer; Number of rounds (default: 12)

            - ``rks`` -- list[int]; Round keys (default: []).

            - ``name`` -- string; The name of the cipher (default: "PRINCE").
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).


        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: prince_cipher = PRINCE_CVL(R=12)
            sage: hex(vec_to_int(prince_cipher(int_to_vec(0x0000000000000123, 64))))
            '0xb58040e6e141cb9a'

        TESTS::
            sage: rks = [
            ....:   0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
            ....:   0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            ....:   0x7ef84f78fd955cb1, 0x85840851f1ac43aa, 0xc882d32f25323c54,
            ....:   0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
            ....: ]
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, rks=rks)
            sage: C = vec_to_int(prince_cipher(int_to_vec(0x0000000000000000, 64)))
            sage: print(hex(C))
            0x818665aa0d02dfda

            sage: rks = [
            ....:   0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
            ....:   0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            ....:   0x7ef84f78fd955cb1, 0x85840851f1ac43aa, 0xc882d32f25323c54,
            ....:   0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
            ....: ]
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, rks=rks)
            sage: C = vec_to_int(prince_cipher(int_to_vec(0xFFFFFFFFFFFFFFFF, 64)))
            sage: print(hex(C))
            0x604ae6ca03c20ada

            # rks = rks ^^ k1 (k1 in this test is 0x0), so rks = RC
            sage: rks = [
            ....:   0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
            ....:   0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            ....:   0x7ef84f78fd955cb1, 0x85840851f1ac43aa, 0xc882d32f25323c54,
            ....:   0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
            ....: ]
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, rks=rks)
            sage: P  = 0x0000000000000000
            sage: k0 = 0xFFFFFFFFFFFFFFFF
            sage: k0_ = 0xFFFFFFFFFFFFFFFE
            sage: C_ = vec_to_int(prince_cipher(int_to_vec(P ^^ k0, 64)))
            sage: C =  C_ ^^ k0_
            sage: print(hex(C))
            0x9fb51935fc3df524

            # rks = rks ^^ k1 (k1 in this test is 0xFFFFFFFFFFFFFFFF)
            # neglect k0 since k0=0x0
            sage: rks = [
            ....:   0xFFFFFFFFFFFFFFFF, 0xece675d1fc8f8cbb, 0x5bf6c7ddd660ce2f,
            ....:   0xf7d1056713b19376, 0xbad7de19c72fec88, 0x41ab9930cb16f393,
            ....:   0x8107b087026aa34e, 0x7a7bf7ae0e53bc55, 0x377d2cd0dacdc3ab,
            ....:   0x9b5aee6a1f1c9ef2, 0x2c4a5c6635f3dc66, 0x3f53d6483683af22
            ....: ]
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, rks=rks)
            sage: P  = 0x0000000000000000
            sage: C = vec_to_int(prince_cipher(int_to_vec(P, 64)))
            sage: print(hex(C))
            0x78a54cbe737bb7ef

            # rks = rks ^^ k1 (k1 in this test is 0xfedcba9876543210)
            # neglect k0 since k0=0x0
            sage: rks = [
            ....:   0xfedcba9876543210, 0xedc530b675244154, 0x5ad582ba5fcb03c0,
            ....:   0xf6f240009a1a5e99, 0xbbf49b7e4e842167, 0x4088dc5742bd3e7c,
            ....:   0x8024f5e08bc16ea1, 0x7b58b2c987f871ba, 0x365e69b753660e44,
            ....:   0x9a79ab0d96b7531d, 0x2d691901bc581189, 0x3e70932fbf2862cd
            ....: ]
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, rks=rks)
            sage: P  = 0x0123456789abcdef
            sage: C = vec_to_int(prince_cipher(int_to_vec(P, 64)))
            sage: print(hex(C))
            0xae25ad3ca8fa9ccf


            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=4)
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
            ....:   prince_cipher.analyse(model_options)
            4112 variables and 12081 clauses were written to ...
            14

            sage: # optional - gurobi # optional - espresso
            sage: from civerly.cipher_implementations.prince \
            ....:   import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=2)
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
            ....:   prince_cipher.analyse(model_options)
            1840 variables and 1873 constraints were written to ...
            2

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.prince \
            ....:   import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=2)
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
            ....:   prince_cipher.analyse(model_options)
            1712 variables and 4641 clauses were written to ...
            1

        """

        if rks is None:
            rks = []
        if rks == []:
            rks = [0] * 12
        else:
            assert len(rks) >= R, "More round keys are needed"
            rks = list(rks[:R])

        # S-layer and the inverse S-layer
        sb = SBox_CVL(prince_S, name="SBox")
        sb_inv = SBox_CVL(prince_S.inverse(), name="SBoxInv")

        s_layer = WordSBoxCipher(4, 16, 16, name="SLayer")
        for j in range(16):
            n = s_layer.add_subcipher(sb, [(s_layer.IN, (j, 0))])
            s_layer.add_output([(n, (0, j))])

        s_layer_inv = WordSBoxCipher(4, 16, 16, name="SLayerInv")
        for j in range(16):
            n = s_layer_inv.add_subcipher(sb_inv, [(s_layer_inv.IN, (j, 0))])
            s_layer_inv.add_output([(n, (0, j))])

        # Linear layers: M, M' and inverse M
        M = LinearLayer_CVL(M_layer, name="M")
        Mprime = LinearLayer_CVL(Mprime_, name="Mprime")
        Minv = LinearLayer_CVL(Minv_, name="Minv")

        # The round key addition layer
        xor_mask = RoundkeyXOR_CVL(64, 0x0, name="XOR")

        # Each forward round: S -> M -> XOR
        fwd_round = WordSBoxCipher(4, 16, 16, name="PRINCE_round_fwd")
        x = fwd_round.IN
        x = fwd_round.add_subcipher(s_layer, [(x, (i, i)) for i in range(16)])
        x = fwd_round.add_subcipher(M, [(x, (i, i)) for i in range(16)])
        n_xor_fwd = fwd_round.add_subcipher(xor_mask, [(x, (i, i)) for i in range(16)])
        fwd_round.add_output([(n_xor_fwd, (i, i)) for i in range(16)])

        # Middle round uses S -> M' -> S^{-1}
        mid_round = WordSBoxCipher(4, 16, 16, name="PRINCE_round_mid")
        x = mid_round.IN
        x = mid_round.add_subcipher(s_layer, [(x, (i, i)) for i in range(16)])
        x = mid_round.add_subcipher(Mprime, [(x, (i, i)) for i in range(16)])
        x = mid_round.add_subcipher(s_layer_inv, [(x, (i, i)) for i in range(16)])
        mid_round.add_output([(x, (i, i)) for i in range(16)])

        # Each backward round: XOR -> M^{-1} -> S^{-1}
        bwd_round = WordSBoxCipher(4, 16, 16, name="PRINCE_round_bwd")
        x = bwd_round.IN
        n_xor_bwd = bwd_round.add_subcipher(xor_mask, [(x, (i, i)) for i in range(16)])
        x = bwd_round.add_subcipher(Minv, [(n_xor_bwd, (i, i)) for i in range(16)])
        x = bwd_round.add_subcipher(s_layer_inv, [(x, (i, i)) for i in range(16)])
        bwd_round.add_output([(x, (i, i)) for i in range(16)])

        # PRINCE core
        prince_core = WordSBoxCipher(4, 16, 16, name=name)
        st = prince_core.IN

        # initial add rks[0]
        if R >= 1:
            xor_mask.const = rks[0]
            st = prince_core.add_subcipher(xor_mask, [(st, (i, i)) for i in range(16)])

        # forward rounds r=1..5
        for r in range(1, min(R, 6)):
            fwd_round.nodes[n_xor_fwd].const = rks[r]
            st = prince_core.add_subcipher(fwd_round, [(st, (i, i)) for i in range(16)])

        # middle round
        if R >= 6:
            st = prince_core.add_subcipher(mid_round, [(st, (i, i)) for i in range(16)])

        # backward rounds r=6..10
        for r in range(6, min(R, 11)):
            bwd_round.nodes[n_xor_bwd].const = rks[r]
            st = prince_core.add_subcipher(bwd_round, [(st, (i, i)) for i in range(16)])

        # final add rks[11]
        if R >= 12:
            xor_mask.const = rks[11]
            st = prince_core.add_subcipher(xor_mask, [(st, (i, i)) for i in range(16)])

        prince_core.add_output([(st, (i, i)) for i in range(16)])
        self.prince_cipher = prince_core

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.prince_cipher
